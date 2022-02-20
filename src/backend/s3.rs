use std::cmp;
use std::io::{Read, Write, copy};
use std::error::Error;
use tokio::runtime::Runtime;
use aws_sdk_s3::Client;
use aws_sdk_s3::Endpoint;
use aws_sdk_s3::ByteStream;
use bytes::Buf;
use http::Uri;

use crate::backend::Backend;


pub struct S3 {
    client: Client,

    // Runtime for the tokio reactor
    rt: Runtime,

    // Buffer for writes, very much shit impl
    buf: Vec<u8>,
    key: String,
    done: bool,
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
            buf: Vec::new(),
            key: "".to_string(),
            done: false,
        })
    }
}


impl Backend for S3 {
    fn list_keys(&self) -> Result<Box<dyn Iterator<Item = String>>, String>{
        let call = self.client.list_objects_v2().
            bucket("test").
            send();

        let res = self.rt.block_on(async {call.await}).unwrap();
        let contents = res.contents.unwrap();

        Ok(Box::new(
            contents.into_iter().map(|x| x.key.unwrap())
        ))
    }

    fn write(&self, key: &str) -> Result<Box<dyn Write>, String> {
        // TODO: Really bad impl
        let mut client = S3::new_endpoint("http://localhost:8333").unwrap();
        client.key = key.to_string();

        Ok(Box::new(client))
    }

    fn read(&mut self, key: &str) -> Result<Box<dyn Read>, String> {
        // TODO: Really bad impl
        let mut client = S3::new_endpoint("http://localhost:8333").unwrap();
        client.key = key.to_string();

        println!("key: {:?}", key);
        Ok(Box::new(client))
    }
}

// TODO: Improve these api big time, we have a instance for read/write
impl Write for S3 {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // So bad, this just collects all data it can
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // We workaround by actually sending the data to s3 here
        let stream = ByteStream::from(self.buf.clone());

        let call = self.client.put_object().
            body(stream).
            bucket("test").
            key(self.key.clone()).
            send();

        let _res = self.rt.block_on(async {call.await}).unwrap();

        Ok(())
    }
}


// TODO: Improve these api big time, we have a instance for read/write
impl Read for S3 {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        if self.buf.is_empty() && !self.done {
            // Do s3 dance to fetch a object and buffer it locally
            let call = self.client.get_object().
                bucket("test").
                key(self.key.clone()).
                send();

            let res = self.rt.block_on(async {call.await}).unwrap();

            let body_call = res.body.collect();
            let data = self.rt.block_on(async {body_call.await.unwrap()});
            let mut data_read = data.reader();

            copy(&mut data_read, &mut self.buf);
            self.done = true;
        }

        // Grab whatever buf.len is off the self.buf
        let split_at = cmp::min(buf.len(), self.buf.len());
        let dat: Vec<u8> = self.buf.drain(0..split_at).collect();
        buf[0..split_at].copy_from_slice(&dat[..]);

        Ok(dat.len())
    }
}


async fn connect(endpoint: &'static str) -> Client {
    let conf = aws_config::load_from_env().await;
    let ep = Endpoint::immutable(Uri::from_static(endpoint));
    let s3_conf = aws_sdk_s3::config::Builder::from(&conf)
        .endpoint_resolver(ep)
        .build();
    Client::from_conf(s3_conf)
}
