use std::cmp;
use std::io::{Read, copy};
use std::error::Error;
use tokio::runtime::Runtime;
use aws_sdk_s3::Client;
use aws_sdk_s3::Endpoint;
use aws_sdk_s3::ByteStream;
use bytes::Buf;
use http::Uri;

// Single threaded but we are on one thread here for now
use std::rc::Rc;

use crate::backend::Backend;


pub struct S3 {
    client: Rc<Client>,
    rt: Rc<Runtime>,
}

impl S3 {
    // TODO: have other creation endpoint that does not take endpoints
    pub fn new_endpoint(endpoint: &'static str) -> Result<Self, Box<dyn Error>> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        let client = rt.block_on(connect(endpoint));

        Ok(S3 {
            client: Rc::new(client),
            rt: Rc::new(rt),
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

    fn write<R: Read>(&self, key: &str, mut reader: R) -> Result<(), String> {
        // TODO: Less bad, still buffer it all in memory, but we can at least
        // manage the read here so we should be able to do something reasonable
        // here at some point
        let mut buf = Vec::new();
        copy(&mut reader, &mut buf).unwrap();

        let stream = ByteStream::from(buf);

        let call = self.client.put_object().
            body(stream).
            bucket("test").
            key(key).
            send();

        let _res = self.rt.block_on(async {call.await}).unwrap();

        Ok(())
    }

    fn read(&mut self, key: &str) -> Result<Box<dyn Read>, String> {
        // Do s3 dance to fetch a object and buffer it locally
        let call = self.client.get_object().
            bucket("test").
            key(key).
            send();

        let res = self.rt.block_on(async {call.await}).unwrap();

        let body_call = res.body.collect();
        let data = self.rt.block_on(async {body_call.await.unwrap()});
        let mut data_read = data.reader();

        let mut buf = Vec::new();
        copy(&mut data_read, &mut buf).unwrap();

        Ok(Box::new(S3Read {
            client: self.client.clone(),
            rt: self.rt.clone(),
            buf,
        }))
    }
}


struct S3Read {
    client: Rc<Client>,
    rt: Rc<Runtime>,
    buf: Vec<u8>,
}

impl Read for S3Read {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
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
