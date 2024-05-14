#!/bin/bash
cd "$(dirname "$0")"

CONTAINER=wget-asm

cd ..
sudo docker build -t $CONTAINER -f test/Dockerfile .
sudo docker run -it --rm -v `pwd`:/app $CONTAINER python3 test/test.py
