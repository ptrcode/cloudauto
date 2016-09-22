#### Check out nops-docker repo and cp the code repo ( ken ) inside ken directory 

```
cd nops-docker
cp  ../ken; nops-docker/ken/
```

#### Bring up the local environment 

`docker-compose up`

For the first time you have to run this, this will bring up all the container. Note, this command doesn't release the prompt, once all the containers are build you can ctrl + c then issue docker-compose start

`docker-compose start`

This will start the containers and mount ken/ken directory in /var/www/html

`docker-compose stop`

it will stop all the containers 

#### Connect to running docker container 

`docker ps`

docker ps will give you container ID, once you have the container ID, you connect to the container use docker exec

docker exec -it $container_id bash`

#### Connect to running docker container

if you are using boot2docker, you can get the IP address by `boot2docker ip`

Docker creates dymamic ports for each listening service, you can get that information by docker ps 

```
docker ps
CONTAINER ID        IMAGE                             COMMAND                CREATED             STATUS              PORTS                                           NAMES
4afa8241f4dd        nopsdocker_ken:latest             "/usr/bin/supervisor   12 minutes ago      Up 6 minutes        0.0.0.0:32777->80/tcp, 0.0.0.0:32776->443/tcp   nopsdocker_ken_1"
```
You should be able to access ken by goign to http://boot2dockerip:32777
