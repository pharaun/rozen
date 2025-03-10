use aws_sdk_s3::types::CompletedPart;
use aws_sdk_s3::types::CompletedMultipartUpload;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client;
use bytes::Buf;
use std::error::Error;
use std::io::{copy, Read, Write};
use std::mem;
use tokio::runtime::Runtime;

// Single threaded but we are on one thread here for now
use std::rc::Rc;

use rcore::buf::flush_buf;

use crate::Remote;
use crate::Typ;

pub struct S3 {
    client: Rc<Client>,
    rt: Rc<Runtime>,
    bucket: String,
}

impl S3 {
    // TODO: have other creation endpoint that does not take endpoints
    pub fn new_endpoint(bucket: &str, endpoint: &'static str) -> Result<Self, Box<dyn Error>> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        let client = rt.block_on(connect(endpoint));

        Ok(S3 {
            client: Rc::new(client),
            rt: Rc::new(rt),
            bucket: bucket.to_string(),
        })
    }
}

impl Remote for S3 {
    fn list_keys(&self, typ: Typ) -> Result<Box<dyn Iterator<Item = String>>, String> {
        let call = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(typ.to_string())
            .send();

        let res = self.rt.block_on(async { call.await }).unwrap();
        let contents = res.contents.unwrap();

        Ok(Box::new(contents.into_iter().map(|x| x.key.unwrap())))
    }

    // TODO: this and the multipart api needs to also do various checksums to pass on to s3
    // so that the s3 can verify the data integrity server-end
    fn write_filename<R: Read>(
        &self,
        typ: Typ,
        filename: &str,
        mut reader: R,
    ) -> Result<(), String> {
        // TODO: Less bad, still buffer it all in memory, but we can at least
        // manage the read here so we should be able to do something reasonable
        // here at some point
        let mut buf = Vec::new();
        copy(&mut reader, &mut buf).unwrap();

        let stream = ByteStream::from(buf);

        let call = self
            .client
            .put_object()
            .body(stream)
            .bucket(&self.bucket)
            .key(format!("{}/{}", typ, filename))
            .send();

        let _res = self.rt.block_on(async { call.await }).unwrap();

        Ok(())
    }

    // TODO: if this is a multipart uploaded it could be possible to fetch each part and
    // verify its checksum and so on before returning it to the backup system?
    fn read_filename(&mut self, typ: Typ, filename: &str) -> Result<Box<dyn Read>, String> {
        // Do s3 dance to fetch a object and buffer it locally
        let call = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(format!("{}/{}", typ, filename))
            .send();

        let res = self.rt.block_on(async { call.await }).unwrap();

        let body_call = res.body.collect();
        let data = self.rt.block_on(async { body_call.await.unwrap() });
        let mut data_read = data.reader();

        let mut buf = Vec::new();
        copy(&mut data_read, &mut buf).unwrap();

        Ok(Box::new(S3Read {
            _client: self.client.clone(),
            _rt: self.rt.clone(),
            buf,
        }))
    }

    fn write_multi_filename(&self, typ: Typ, key: &str) -> Result<Box<dyn Write>, String> {
        let call = self
            .client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(format!("{}/{}", typ, key))
            .send();

        let res = self.rt.block_on(async { call.await }).unwrap();

        Ok(Box::new(S3Multi {
            client: self.client.clone(),
            rt: self.rt.clone(),
            key: key.to_string(),
            id: res.upload_id.unwrap(),
            bucket: self.bucket.clone(),
            part: Vec::new(),
            part_id: 1,
            t_buf: Vec::new(),
            typ,
        }))
    }
}

struct S3Multi {
    client: Rc<Client>,
    rt: Rc<Runtime>,
    key: String,
    id: String,
    bucket: String,
    part: Vec<CompletedPart>,
    part_id: i32,

    // Buffer it till 6mb then upload it as a new part
    t_buf: Vec<u8>,
    typ: Typ,
}

const BUFFER_TARGET: usize = 6 * 1024 * 1024;

impl Write for S3Multi {
    fn write(&mut self, in_buf: &[u8]) -> Result<usize, std::io::Error> {
        // append to t_buf
        self.t_buf.extend(in_buf);
        self.upload_part(false);

        Ok(in_buf.len())
    }

    // TODO: not sure if this is proper use of flush or if we should have a finalize call instead
    fn flush(&mut self) -> Result<(), std::io::Error> {
        // Finalaize the stream
        self.upload_part(true);

        let call = self
            .client
            .complete_multipart_upload()
            .bucket(&self.bucket)
            .key(format!("{}/{}", &self.typ.to_string(), &self.key))
            .upload_id(self.id.clone())
            .multipart_upload(
                CompletedMultipartUpload::builder()
                    .set_parts(Some(self.part.clone()))
                    .build(),
            )
            .send();

        let _res = self.rt.block_on(async { call.await }).unwrap();
        Ok(())
    }
}

impl S3Multi {
    fn upload_part(&mut self, last: bool) {
        // If last part to upload *or* at least 6mb accumulated upload
        if (last && !self.t_buf.is_empty()) || self.t_buf.len() >= BUFFER_TARGET {
            // Swap the self.t_buf with a empty one and own it
            let mut t_buf = Vec::new();
            mem::swap(&mut self.t_buf, &mut t_buf);

            let stream = ByteStream::from(t_buf);
            let call = self
                .client
                .upload_part()
                .body(stream)
                .bucket(&self.bucket)
                .key(format!("{}/{}", &self.typ.to_string(), &self.key))
                .upload_id(self.id.clone())
                .part_number(self.part_id)
                .send();

            let res = self.rt.block_on(async { call.await }).unwrap();

            // Collect info to make a CompletePart to then record in finalize
            self.part.push(
                CompletedPart::builder()
                    .e_tag(res.e_tag.unwrap())
                    .part_number(self.part_id)
                    .build(),
            );

            // Increment the part number, clear the buffer
            self.part_id += 1;
        }
    }
}

// TODO: properly implement streaming
struct S3Read {
    _client: Rc<Client>,
    _rt: Rc<Runtime>,
    buf: Vec<u8>,
}

impl Read for S3Read {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        Ok(flush_buf(&mut self.buf, buf))
    }
}

async fn connect(endpoint: &'static str) -> Client {
    let conf = aws_config::load_from_env().await;
    let s3_conf = aws_sdk_s3::config::Builder::from(&conf)
        .endpoint_url(endpoint)
        .build();
    Client::from_conf(s3_conf)
}
