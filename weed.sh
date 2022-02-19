#!/bin/bash
weed server -s3 -master.port=9333 -volume.port=8080 -dir='data' -ip='127.0.0.1' -volume.max=1
