use clap::Parser;
use hyper::{
    header::AUTHORIZATION,
    service::{make_service_fn, service_fn},
    Body, Method, Request, Response, Server, StatusCode,
};
use log::{error, info};
use rusoto_core::{
    region::ParseRegionError,
    request::{HttpClient as RusotoHttpClient, TlsError},
    RusotoError,
};
use rusoto_credential::StaticProvider;
use rusoto_route53::{ChangeResourceRecordSetsError, Route53, Route53Client};
use serde_derive::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

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
    #[error("Unable to initialize TLS client: {0}")]
    Tls(#[from] TlsError),
}

impl DynDnsError {
    fn status_code(&self) -> StatusCode {
        match self {
            DynDnsError::InvalidUser => StatusCode::FORBIDDEN,
            DynDnsError::InvalidHostname
            | DynDnsError::InvalidIpAddress
            | DynDnsError::InvalidQueryParams
            | DynDnsError::InvalidRequestHeaders
            | DynDnsError::InvalidRequestPath
            | DynDnsError::InvalidRequestUrl => StatusCode::BAD_REQUEST,
            DynDnsError::InvalidRequestMethod => StatusCode::METHOD_NOT_ALLOWED,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn public_error(&self) -> String {
        match self {
            DynDnsError::InvalidUser
            | DynDnsError::InvalidHostname
            | DynDnsError::InvalidIpAddress
            | DynDnsError::InvalidQueryParams
            | DynDnsError::InvalidRequestHeaders
            | DynDnsError::InvalidRequestMethod
            | DynDnsError::InvalidRequestPath
            | DynDnsError::InvalidRequestUrl => self.to_string(),
            _ => "Internal Server Error".to_string(),
        }
    }

    fn log_level(&self) -> Option<log::Level> {
        match self {
            DynDnsError::InvalidUser => None,
            DynDnsError::InvalidHostname
            | DynDnsError::InvalidIpAddress
            | DynDnsError::InvalidQueryParams
            | DynDnsError::InvalidRequestHeaders
            | DynDnsError::InvalidRequestMethod
            | DynDnsError::InvalidRequestPath
            | DynDnsError::InvalidRequestUrl => Some(log::Level::Warn),
            _ => Some(log::Level::Error),
        }
    }
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
    info!("Reading config from: {}", args.config.display());

    let config_bytes = std::fs::read(args.config)?;
    let config: Config = toml::from_slice(&config_bytes)?;

    let addr = ([0, 0, 0, 0], config.port).into();

    let dns_client = DnsClient::new(&config)?;
    let context = DynDnsContext::new(dns_client, config.users);
    let dyn_dns_service = make_service_fn(move |_conn| {
        let context = context.clone();
        let service = service_fn(move |req| handler(context.clone(), req));

        async move { Ok::<_, Infallible>(service) }
    });

    info!("Starting listening on: {}", addr);
    let server = Server::bind(&addr).serve(dyn_dns_service);

    if let Err(e) = server.await {
        error!("Fatal server error: {}", e);
    }

    Ok(())
}

async fn handler(
    ctx: DynDnsContext,
    req: Request<Body>,
) -> Result<Response<Body>, std::convert::Infallible> {
    let res = handle_request(ctx, req)
        .await
        .unwrap_or_else(|err| err.into());

    Ok(res)
}

async fn handle_request(
    ctx: DynDnsContext,
    req: Request<Body>,
) -> Result<Response<Body>, DynDnsError> {
    let (ip, hostname) = ctx.get_req_ip(req)?;
    let _dns_id = ctx.dns.set_ip_record(ip, hostname).await?;
    let res = Response::new(Body::from(format!("good {}", ip)));

    Ok(res)
}

impl Into<Response<Body>> for DynDnsError {
    fn into(self) -> Response<Body> {
        let status = self.status_code();
        let error_msg = self.public_error();

        if let Some(level) = self.log_level() {
            log::log!(level, "{} {}: {} {:?}", status, error_msg, self, self);
        }

        let mut res = Response::new(Body::from(error_msg));
        *res.status_mut() = status;
        res
    }
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

    fn get_req_ip(&self, req: Request<Body>) -> Result<(IpAddr, String), DynDnsError> {
        info!("Request to: {}", req.uri());
        let url = Url::parse("http://example.com")
            .and_then(|u| u.join(&req.uri().to_string()))
            .map_err(|_e| DynDnsError::InvalidRequestUrl)?;

        if req.method() != &Method::GET {
            return Err(DynDnsError::InvalidRequestMethod);
        }

        if url.path() != "/nic/update" {
            return Err(DynDnsError::InvalidRequestPath);
        }

        let header_auth = req
            .headers()
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split_once(' '))
            .and_then(|(auth, value)| {
                if auth.eq_ignore_ascii_case("basic") {
                    Some(value)
                } else {
                    None
                }
            })
            .ok_or(DynDnsError::InvalidRequestHeaders)?;

        let user = self.get_user(header_auth).ok_or(DynDnsError::InvalidUser)?;
        let query_params: HashMap<String, String> = url.query_pairs().into_owned().collect();
        let hostname = query_params.get("hostname");
        let ip = query_params.get("myip");

        let (hostname, ip) = hostname.zip(ip).ok_or(DynDnsError::InvalidQueryParams)?;

        if user.hosts.iter().any(|h| h == hostname) {
            IpAddr::from_str(ip)
                .map(|ip| (ip, hostname.to_owned()))
                .map_err(|_| DynDnsError::InvalidIpAddress)
        } else {
            Err(DynDnsError::InvalidHostname)
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
        let dispatcher = RusotoHttpClient::new()?;
        let client = Route53Client::new_with(dispatcher, creds, config.aws_region.parse()?);
        Ok(DnsClient { config, client })
    }

    async fn set_ip_record(
        &self,
        ip: IpAddr,
        hostname: impl AsRef<str>,
    ) -> Result<DnsChangeId, DynDnsError> {
        info!("Attemping IP update: {}, {}", ip, hostname.as_ref());
        let addr_type = match ip {
            IpAddr::V4(_) => "A",
            IpAddr::V6(_) => "AAAA",
        };

        self.set_dns_record(addr_type, format!("{}.", hostname.as_ref()), ip.to_string())
            .await
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
        Ok(DnsChangeId(change.change_info.id))
    }
}
