use std::io::{Read, Write};
use std::error::Error;
use tokio::runtime::Runtime;
use aws_sdk_s3::Client;
use aws_sdk_s3::Endpoint;
use http::Uri;

use crate::backend::Backend;


pub struct S3 {
    client: Client,

    // Runtime for the tokio reactor
    rt: Runtime,
}

impl S3 {
    // TODO: have other creation endpoint that does not take endpoints
    pub fn new_endpoint(endpoint: &'static str) -> Result<Self, Box<dyn Error>> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        let client = rt.block_on(connect(endpoint));

        Ok(S3 {
            client,
            rt,
        })
    }
}


//impl Backend for S3 {
//    fn list_keys(&self) -> Result<Box<dyn Iterator<Item = String>>, String>{
//    }
//
//    fn write(&self, key: &str) -> Result<Box<dyn Write>, String> {
//    }
//
//    fn read(&mut self, key: &str) -> Result<Box<dyn Read>, String> {
//    }
//}


async fn connect(endpoint: &'static str) -> Client {
    let conf = aws_config::load_from_env().await;
    let ep = Endpoint::immutable(Uri::from_static(endpoint));
    let s3_conf = aws_sdk_s3::config::Builder::from(&conf)
        .endpoint_resolver(ep)
        .build();
    Client::from_conf(s3_conf)
}
