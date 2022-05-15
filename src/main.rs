use clap::Parser;
use hyper::{
    header::{HeaderValue, AUTHORIZATION},
    service::{make_service_fn, service_fn},
    Body, Method, Request, Response, Server, StatusCode,
};
use log::{error, info, warn};
use rusoto_core::{region::ParseRegionError, request::HttpClient as RusotoHttpClient, RusotoError};
use rusoto_credential::StaticProvider;
use rusoto_route53::{ChangeResourceRecordSetsError, Route53, Route53Client};
use serde_derive::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use std::convert::Infallible;
use std::fs::File;
use std::io::Read;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::{collections::HashMap, path::PathBuf};

#[derive(Error, Debug)]
enum DynDnsError {
    #[error("Could not parse supplied IP address")]
    InvalidIpAddress,
    #[error("The hostname provided is not permitted for this user")]
    InvalidHostname,
    #[error("The myip and hostname query parameters are required")]
    InvalidQueryParams,
    #[error("Invalid username or password")]
    InvalidUser,
    #[error("Basic Authorization header required")]
    InvalidRequestHeaders,
    #[error("Requests must be sent to /nic/update")]
    InvalidRequestPath,
    #[error("Only GET requests are supported")]
    InvalidRequestMethod,
    #[error("Invalid request URL")]
    InvalidRequestUrl,
    #[error("DNS change request error: {0}")]
    ChangeRequest(#[from] RusotoError<ChangeResourceRecordSetsError>),
    #[error("Invalid AWS region: {0}")]
    InvalidAwsRegion(#[from] ParseRegionError),
    #[error("Io Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Toml parse error: {0}")]
    Toml(#[from] toml::de::Error),
}

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, default_value = "./config.toml")]
    config: PathBuf,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Config {
    aws_access_key: String,
    aws_secret_key: String,
    aws_region: String,
    aws_zone_id: String,
    users: Vec<User>,
    port: u16,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct User {
    user_name: String,
    password: String,
    hosts: Vec<String>,
}

impl User {
    fn auth_string(&self) -> String {
        let s = format!("{}:{}", self.user_name, self.password);
        base64::encode(&s)
    }
}

#[tokio::main]
async fn main() -> Result<(), DynDnsError> {
    env_logger::init();
    let args = Args::parse();
    let mut config_file = File::open(args.config)?;
    let mut config_bytes = Vec::new();
    config_file.read_to_end(&mut config_bytes)?;
    let config: Config = toml::from_slice(&config_bytes)?;

    let addr = ([0, 0, 0, 0], config.port).into();
    info!("Starting listening on: {}", addr);

    let dns_client = DnsClient::new(&config)?;
    let context = DynDnsContext::new(dns_client, config.users);
    let dyn_dns_service = make_service_fn(move |_conn| {
        let context = context.clone();
        let service = service_fn(move |req| handler(context.clone(), req));

        async move { Ok::<_, Infallible>(service) }
    });

    let server = Server::bind(&addr).serve(dyn_dns_service);

    if let Err(e) = server.await {
        error!("Fatal server error: {}", e);
    }

    Ok(())
}

async fn call(ctx: DynDnsContext, req: Request<Body>) -> Result<Response<Body>, DynDnsError> {
    let (ip, hostname) = ctx.get_req_ip(req)?;
    let _dns_id = ctx.dns.set_ip_record(ip, hostname).await?;
    let res = Response::new(Body::from(format!("good {}", ip)));

    Ok(res)
}

async fn handler(
    ctx: DynDnsContext,
    req: Request<Body>,
) -> Result<Response<Body>, std::convert::Infallible> {
    let res = call(ctx, req).await.unwrap_or_else(handle_err);

    Ok(res)
}

fn handle_err(err: DynDnsError) -> Response<Body> {
    let (status, res) = match err {
        DynDnsError::InvalidUser => (StatusCode::FORBIDDEN, err.to_string()),

        DynDnsError::InvalidHostname
        | DynDnsError::InvalidIpAddress
        | DynDnsError::InvalidQueryParams
        | DynDnsError::InvalidRequestHeaders
        | DynDnsError::InvalidRequestMethod
        | DynDnsError::InvalidRequestPath
        | DynDnsError::InvalidRequestUrl => {
            warn!("Bad Request: {:?}", err);
            (StatusCode::BAD_REQUEST, err.to_string())
        }
        err => {
            error!("Server error: {} {:?}", err, err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error".to_string(),
            )
        }
    };

    let mut res = Response::new(Body::from(res));
    *res.status_mut() = status;
    res
}

#[derive(Clone)]
struct DynDnsContext {
    dns: Arc<DnsClient>,
    users: Arc<HashMap<String, User>>,
}

impl DynDnsContext {
    fn new(dns: DnsClient, default_users: impl IntoIterator<Item = User>) -> Self {
        let mut users = HashMap::new();
        for user in default_users {
            let auth_string = user.auth_string();
            users.insert(auth_string, user);
        }

        Self {
            dns: Arc::new(dns),
            users: Arc::new(users),
        }
    }

    fn get_user(&self, auth_string: impl AsRef<str>) -> Option<&User> {
        self.users.get(auth_string.as_ref())
    }

    fn get_req_ip(&self, req: Request<Body>) -> Result<(std::net::IpAddr, String), DynDnsError> {
        info!("Request to: {}", req.uri());
        let url = Url::parse("http://example.com")
            .and_then(|u| u.join(&req.uri().to_string()))
            .map_err(|_e| DynDnsError::InvalidRequestUrl)?;
        if req.method() != &Method::GET {
            return Err(DynDnsError::InvalidRequestMethod);
        } else if url.path() != "/nic/update" {
            return Err(DynDnsError::InvalidRequestPath);
        } else {
            let header = req.headers().get(AUTHORIZATION).map(HeaderValue::to_str);
            let header = if let Some(Ok(value)) = header {
                let lower = value.to_lowercase();
                if lower.starts_with("basic ") {
                    Some(&value[6..])
                } else {
                    None
                }
            } else {
                None
            };
            let header = header.ok_or(DynDnsError::InvalidRequestHeaders)?;
            let user = self.get_user(header).ok_or(DynDnsError::InvalidUser)?;
            let query_params: HashMap<String, String> = url.query_pairs().into_owned().collect();
            let hostname = query_params.get("hostname");
            let ip = query_params.get("myip");

            if let (Some(hostname), Some(ip)) = (hostname, ip) {
                if user.hosts.iter().any(|h| h == hostname) {
                    IpAddr::from_str(ip)
                        .map(|ip| (ip, hostname.to_owned()))
                        .map_err(|_| DynDnsError::InvalidIpAddress)
                } else {
                    Err(DynDnsError::InvalidHostname)
                }
            } else {
                Err(DynDnsError::InvalidQueryParams)
            }
        }
    }
}

struct DnsChangeId(String);

struct DnsClient {
    config: Config,
    client: Route53Client,
}

impl DnsClient {
    fn new(config: &Config) -> Result<DnsClient, DynDnsError> {
        let config = config.clone();
        let creds = StaticProvider::new_minimal(
            config.aws_access_key.clone(),
            config.aws_secret_key.clone(),
        );
        let dispatcher = RusotoHttpClient::new().unwrap();
        let client = Route53Client::new_with(dispatcher, creds, config.aws_region.parse()?);
        Ok(DnsClient { config, client })
    }

    async fn set_ip_record(
        &self,
        ip: IpAddr,
        hostname: impl AsRef<str>,
    ) -> Result<DnsChangeId, DynDnsError> {
        info!("Attemping IP update: {}, {}", ip, hostname.as_ref());
        match ip {
            IpAddr::V4(ip) => {
                self.set_dns_record("A", format!("{}.", hostname.as_ref()), ip.to_string())
                    .await
            }
            IpAddr::V6(ip) => {
                self.set_dns_record("AAAA", format!("{}.", hostname.as_ref()), ip.to_string())
                    .await
            }
        }
    }

    async fn set_dns_record<K: Into<String>, N: Into<String>, V: Into<String>>(
        &self,
        kind: K,
        name: N,
        value: V,
    ) -> Result<DnsChangeId, DynDnsError> {
        use rusoto_route53::{
            Change, ChangeBatch, ChangeResourceRecordSetsRequest, ResourceRecord, ResourceRecordSet,
        };

        let kind = kind.into();
        let name = name.into();
        let value = value.into();

        let record = ResourceRecord { value };

        let record_set = ResourceRecordSet {
            name,
            resource_records: Some(vec![record]),
            ttl: Some(300),
            type_: kind,
            ..Default::default()
        };

        let change = Change {
            action: String::from("UPSERT"),
            resource_record_set: record_set,
        };

        let change_batch = ChangeBatch {
            changes: vec![change],
            comment: Some(String::from("Automated Dyndns update")),
        };

        let change_req = ChangeResourceRecordSetsRequest {
            change_batch,
            hosted_zone_id: self.config.aws_zone_id.clone(),
        };

        info!("Submitting DNS change");
        let change = self.client.change_resource_record_sets(change_req).await?;

        info!("DNS change submitted");
        let id = change
            .change_info
            .id
            .get(8..)
            .expect("Id should be prefixed with '/change/'"); //Remove '/change/' prefix
        Ok(DnsChangeId(id.into()))
    }
}
