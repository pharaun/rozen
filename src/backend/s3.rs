use std::cmp;
use std::io::{Read, copy};
use std::error::Error;
use tokio::runtime::Runtime;
use aws_sdk_s3::Client;
use aws_sdk_s3::Endpoint;
use aws_sdk_s3::ByteStream;
use aws_sdk_s3::model::CompletedMultipartUpload;
use aws_sdk_s3::model::CompletedPart;
use bytes::Buf;
use http::Uri;

// Single threaded but we are on one thread here for now
use std::rc::Rc;

use crate::backend::Backend;
use crate::backend::MultiPart;
use crate::buf::flush_buf;


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

    fn multi_write(&self, key: &str) -> Result<Box<dyn MultiPart>, String> {
        let call = self.client.create_multipart_upload().
            bucket("test").
            key(key).
            send();

        let res = self.rt.block_on(async {call.await}).unwrap();

        Ok(Box::new(S3Multi {
            client: self.client.clone(),
            rt: self.rt.clone(),
            key: key.to_string(),
            id: res.upload_id.unwrap(),
            part: Vec::new(),
        }))
    }
}

struct S3Multi {
    client: Rc<Client>,
    rt: Rc<Runtime>,
    key: String,
    id: String,
    part: Vec<CompletedPart>,
}

impl MultiPart for S3Multi {
    fn write(&mut self, reader: &mut dyn Read) -> Result<(), String> {
        // TODO: for now do it in just one shot and buffer it all in memory
        let mut buf = Vec::new();
        copy(reader, &mut buf).unwrap();

        let stream = ByteStream::from(buf);

        // TODO: we just hardcode in part number (1) but we should
        // collect it and store it in order the parts should be in
        let call = self.client.upload_part().
            body(stream).
            bucket("test").
            key(self.key.clone()).
            upload_id(self.id.clone()).
            part_number(1).
            send();

        let res = self.rt.block_on(async {call.await}).unwrap();

        // Collect info to make a CompletePart to then record in finalize
        self.part.push(
            CompletedPart::builder().
                e_tag(res.e_tag.unwrap()).
                part_number(1).
                build()
        );

        Ok(())
    }

    fn finalize(self: Box<Self>) -> Result<(), String> {
        let call = self.client.complete_multipart_upload().
            bucket("test").
            key(self.key.clone()).
            upload_id(self.id.clone()).
            multipart_upload(
                CompletedMultipartUpload::builder().
                    set_parts(Some(self.part)).
                    build()
            ).send();

        let _res = self.rt.block_on(async {call.await}).unwrap();
        Ok(())
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
        let dat_len = flush_buf(&mut self.buf, buf);
        Ok(dat_len)
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
