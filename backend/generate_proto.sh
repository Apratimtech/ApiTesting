#!/bin/bash

python -m grpc_tools.protoc \
-I ./app/grpc_proto/protos \
--python_out=./app/grpc_proto/generated \
--grpc_python_out=./app/grpc_proto/generated \
./app/grpc_proto/protos/analyzer.proto
