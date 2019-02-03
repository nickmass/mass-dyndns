use failure::{Error, Fail};
use futures::{Future, IntoFuture};
use hyper::header::{HeaderValue, AUTHORIZATION};
use hyper::service::service_fn;
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use log::{error, info, warn};
use rusoto_core::request::HttpClient as RusotoHttpClient;
use rusoto_credential::StaticProvider;
use rusoto_route53::{Route53, Route53Client};
use serde_derive::{Deserialize, Serialize};
use url::Url;

use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

#[derive(Fail, Debug)]
enum DynDnsError {
    #[fail(display = "Could not parse supplied IP address")]
    InvalidIpAddress,
    #[fail(display = "The hostname provided is not permitted for this user")]
    InvalidHostname,
    #[fail(display = "The myip and hostname query parameters are required")]
    InvalidQueryParams,
    #[fail(display = "Invalid username or password")]
    InvalidUser,
    #[fail(display = "Basic Authorization header required")]
    InvalidRequestHeaders,
    #[fail(display = "Requests must be sent to /nic/update")]
    InvalidRequestPath,
    #[fail(display = "Only GET requests are supported")]
    InvalidRequestMethod,
    #[fail(display = "Invalid request URL")]
    InvalidRequestUrl,
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

fn main() -> Result<(), Error> {
    env_logger::init();
    let mut config_file = File::open("./config.toml")?;
    let mut config_bytes = Vec::new();
    config_file.read_to_end(&mut config_bytes)?;
    let config: Config = toml::from_slice(&config_bytes)?;

    let addr = ([0, 0, 0, 0], config.port).into();
    info!("Starting listening on: {}", addr);

    let dns_client = DnsClient::new(&config)?;
    let service = Arc::new(DynDnsService::new(dns_client, config.users));
    let dyn_dns_service = move || {
        let service = service.clone();
        service_fn(move |req| service.call(req).map_err(|e| e.compat()))
    };

    let server = Server::bind(&addr).serve(dyn_dns_service);

    hyper::rt::run(server.map_err(|e| error!("FATAL ERROR: {} {:?}", e, e)));

    Ok(())
}

struct DynDnsService {
    dns: Arc<DnsClient>,
    users: HashMap<String, User>,
}

impl DynDnsService {
    fn new(dns: DnsClient, default_users: impl IntoIterator<Item = User>) -> Self {
        let mut users = HashMap::new();
        for user in default_users {
            let auth_string = user.auth_string();
            users.insert(auth_string, user);
        }

        Self {
            dns: Arc::new(dns),
            users,
        }
    }

    fn call(&self, req: Request<Body>) -> impl Future<Item = Response<Body>, Error = Error> {
        let dns = self.dns.clone();
        self.get_req_ip(req)
            .and_then(|(ip, hostname)| Ok(dns.set_ip_record(ip, hostname).join(Ok(ip))))
            .into_future()
            .flatten()
            .and_then(|(_dns_id, ip)| Ok(Response::new(Body::from(format!("good {}", ip)))))
            .or_else(|error| Ok(Self::handle_err(error)))
    }

    fn handle_err(err: Error) -> Response<Body> {
        let (status, res) = match err.downcast::<DynDnsError>() {
            Ok(e @ DynDnsError::InvalidUser) => (StatusCode::FORBIDDEN, e.to_string()),
            Ok(err) => {
                warn!("Bad Request: {:?}", err);
                (StatusCode::BAD_REQUEST, err.to_string())
            }
            Err(err) => {
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

    fn get_user(&self, auth_string: impl AsRef<str>) -> Option<&User> {
        self.users.get(auth_string.as_ref())
    }

    fn get_req_ip(&self, req: Request<Body>) -> Result<(std::net::IpAddr, String), Error> {
        info!("Request to: {}", req.uri());
        let url = Url::parse("http://example.com")
            .and_then(|u| u.join(&req.uri().to_string()))
            .map_err(|_e| DynDnsError::InvalidRequestUrl)?;
        if req.method() != &Method::GET {
            return Err(DynDnsError::InvalidRequestMethod.into());
        } else if url.path() != "/nic/update" {
            return Err(DynDnsError::InvalidRequestPath.into());
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
                        .map_err(|_| DynDnsError::InvalidIpAddress.into())
                } else {
                    Err(DynDnsError::InvalidHostname.into())
                }
            } else {
                Err(DynDnsError::InvalidQueryParams.into())
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
    fn new(config: &Config) -> Result<DnsClient, Error> {
        let config = config.clone();
        let creds = StaticProvider::new_minimal(
            config.aws_access_key.clone(),
            config.aws_secret_key.clone(),
        );
        let dispatcher = RusotoHttpClient::new().unwrap();
        let client = Route53Client::new_with(dispatcher, creds, config.aws_region.parse()?);
        Ok(DnsClient { config, client })
    }

    fn set_ip_record(
        &self,
        ip: IpAddr,
        hostname: impl AsRef<str>,
    ) -> impl Future<Item = DnsChangeId, Error = Error> {
        info!("Attemping IP update: {}, {}", ip, hostname.as_ref());
        match ip {
            IpAddr::V4(ip) => {
                self.set_dns_record("A", format!("{}.", hostname.as_ref()), ip.to_string())
            }
            IpAddr::V6(ip) => {
                self.set_dns_record("AAAA", format!("{}.", hostname.as_ref()), ip.to_string())
            }
        }
    }

    fn set_dns_record<K: Into<String>, N: Into<String>, V: Into<String>>(
        &self,
        kind: K,
        name: N,
        value: V,
    ) -> impl Future<Item = DnsChangeId, Error = Error> {
        use rusoto_route53::{
            Change, ChangeBatch, ChangeResourceRecordSetsRequest, ResourceRecord, ResourceRecordSet,
        };

        let kind = kind.into();
        let name = name.into();
        let value = value.into();

        let record = ResourceRecord { value: value };

        let record_set = ResourceRecordSet {
            name: name,
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
            change_batch: change_batch,
            hosted_zone_id: self.config.aws_zone_id.clone(),
        };

        info!("Submitting DNS change");
        self.client
            .change_resource_record_sets(change_req)
            .and_then(|change| {
                info!("DNS change submitted");
                let id = change
                    .change_info
                    .id
                    .get(8..)
                    .expect("Id should be prefixed with '/change/'"); //Remove '/change/' prefix
                Ok(DnsChangeId(id.into()))
            })
            .from_err()
    }
}
