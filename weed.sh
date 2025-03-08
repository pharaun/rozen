#!/bin/bash
dir=$(mktemp -d)
weed server -s3 -master.port=9333 -volume.port=8080 -dir="$dir" -ip='127.0.0.1'
