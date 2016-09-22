From ubuntu
WORKDIR /opt/dynamodb
RUN export DEBIAN_FRONTEND=noninteractive ;apt-get update ;apt-get install -yq openjdk-7-jre-headless curl ;apt-get clean all
RUN /usr/bin/curl -L http://dynamodb-local.s3-website-us-west-2.amazonaws.com/dynamodb_local_latest.tar.gz | /bin/tar xz
EXPOSE 8001
CMD ["/usr/bin/java","-Djava.library.path=./DynamoDBLocal_lib","-jar","DynamoDBLocal.jar","-port","8001"]