set -e
docker build --target aesm -t sgx_aesm -f ./Dockerfile ./

docker build --target chall -t basic_guide -f ./Dockerfile ./

docker volume create --driver local --opt type=tmpfs --opt device=tmpfs --opt o=rw aesmd-socket

docker-compose up -d
