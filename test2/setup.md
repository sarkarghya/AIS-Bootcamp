docker system prune --all --volumes

docker stop $(docker ps -aq)
docker rm $(docker ps -aq)

docker build --network=host . -t mydocker
docker run --network host --privileged --cgroupns=host -it mydocker /bin/sh

docker run --privileged -it mydocker /bin/sh