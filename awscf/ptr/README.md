# Cyclops

## Overview

A Python library and command line interface to manage a small application cloud.

Cyclops is made up of "environments". Each environment is a high-level grouping of routing, compute resource and services.

Each environment is a set of associated 3rd party and Amazon APIs, providing compute resource and services for hosting app servers.

Each app is deployed as a stateless container (using Docker containers) into a pool of compute resource (via EC2 Container Service).

Public traffic is routed through to apps (via Route 53 and Elastic Load Balancer), and apps connect to a range of backend services ("backends") that provide data persistence and other functionality (S3, RDS, ElasticCache, SOLR).

An app is updated by making changes to its Dockerfile and then a push > build > pull flow that encourages versioning of state/config changes to an app, and discourages direct access to an app's machine or runtime environment.

## High-level design

<img src="https://docs.google.com/drawings/d/1YRfzZQvK5FTuLExr8zZREi4uQNYLEwxdGJSCdcpXLl4/pub?w=960&amp;h=720">

## Concepts

We use a few concepts that may seem interchangeable/unclear. To provide clarity, these are the key concepts in a Cyclops cloud.

### Platform

The entire collection of all tooling and APIs that make up Cyclops. At a broad level, this means:

* The Cyclops CLI
* A DockerHub account
* A GitHub account
* A Sentry account
* An AWS account
  * The specific features/APIs of AWS that we actually use
    * Some services are global, and therefore "platform specific" like SES
    * Some services are per environment, like RDS DB instances

### Environment

A conceptual entity that apps are deployed into. For example: "staging" or "production". An environment is really just a collection of loosely coupled tools and APIs.

At this stage, setting up an environment means:

* A platform has been setup, particularly an AWS account and some Docker Images on DockerHub
* A new CloudFormation stack has been configured in AWS, and an associated EC2 Container service cluster
  * Cluster added first with name, like "staging" or "production", then CloudFormation stack uses that cluster to configure compute resources etc.
* An RDS instance
* A SES instance
* An ElasticCache instance

### Cluster

Each environment has its own cluster. A Cluster is a pool of EC2 compute resource that containers are deployed into.

### App

An app is a distinct customer application that we serve from an environment. An app could have one or more linked containers (eg: the app container, and a linked search container).

### Service

In essence, the cloud is a pool of compute resources for applications, surrounded by a range of **services**. So for us, services mean things like the DNS (Route 53), load balancer (ELB), database (RDS), key value store (ElasticCache), as well as more external elements like the exception logger (Sentry) and so on.

## Services we use

### Amazon Services

We rely heavily on Amazon APIs wherever possible- the cloud does not have an abstraction that is provider-agnostic.

This has been a conscious decision to focus on the deliverable via the most immediate path possible. We also employ other 3rd party services where possible for the same reason.

#### VPC - isolated cloud resources

[Read more](http://aws.amazon.com/vpc/)

Create a set of isolated resources.

#### CloudFormation - resource management

[Read more](http://aws.amazon.com/cloudformation/)

Template-driven creation and management of resources. We use this at several levels: a general platform configuration, per-environment configuration, and per app configuration. In CloudFormation, each config is called a "Stack".

#### Route 53 - DNS

[Read more](http://aws.amazon.com/route53/)

DNS management. We have a hosted zone per environment.

#### Elastic Load Balancing

[Read more](http://aws.amazon.com/elasticloadbalancing/)

Manage traffic into containers.

#### ECS - Elastic Container Services

[Read more](http://aws.amazon.com/ecs/)

A container management abstraction over EC2 compute resource.

#### RDS - Relation Database Service

[Read more](http://aws.amazon.com/rds/)

An SQL database service using Postgres.

#### ElasticCache

[Read more](http://aws.amazon.com/elasticache/)

A key:value store using Redis.

#### SES - Simple Email Service

[Read more](http://aws.amazon.com/ses/)

A transactional email backend. We use the SMTP interface.

#### CloudWatch

[Read more](http://aws.amazon.com/cloudwatch/)

Monitoring of resources in the platform.

### Custom services

#### Solr

Search has proved an issue, as we can't take advantage of Amazon's search APIs, and therefore we need to manage our own resources. After checking several options, the candidates come down to:

* Maintaining our own SolrCloud cluster
* Deploying a search container with each app using the Docker linked containers API

**Not implemented**

### Other services

#### Docker Hub

[Read more](https://hub.docker.com)

Automated builds of Dockerfiles before pulling into our container cluster.

#### GitHub

[Read more](https://github.com)

Versioning of all files for deployment - keeps log of deployment history and configuration applied to any given app.

#### Sentry

[Read more](https://getsentry.com)

Application-level exception logging.

## How it works


Ensure you have an aws config for boto3 at `~/.aws/config`. It should look like this:

```
[default]
region = us-east-1
aws_access_key_id = {YOUR_KEY}
aws_secret_access_key = {YOUR_SECRET}
```

### Platform setup

We need to start by setting up our core platform. Setup order is important, as a platform setup is a manual, one-time configuration, with dependencies from one step to the next.

**NOTE**: All the docs below refer to the `cyclops` executable. This is currently only available as `python CkanCli.py`, so replace accordingly.

1. Ensure you have Cyclops on your local machine, and install the dependencies. [Cyclops lives here](https://github.com/okfn/cyclops)
2. Create a new AWS account (not strictly necessary but possibly easier, and it is what we have done for initial setup)
3. Create a new bucket on S3 for Cyclops to work with. This will hold things like configuration templates. The bucket should be private. Example: `cyclops-cloud`
4. Create a file called `config.json` in your local working directory (For simplicity, ensure that the Cyclops repository root is your working directory, and copy the existing `config.example.json` to `config.json` as a starting point). This file will be used to add specific values required for your platform setup (don't worry, `config.json` is gitignored).
5. Now we want to populate the `config.json` with some things we need now: `user.key`, `user.secret`, `platform.region`, `platform.config_bucket`, `cluster.keyname`
6. Once we have those essential settings in our config, we'll save our CloudFormation template for the **platform** (`config/platform.json`) to S3 with this command: `cyclops config push platform`. The response to this command will be the S3 URL for the platform config, which you will need in the next step.
7. Also, we'll save our port mapping file "database", which keeps track of port allocation (`config/ports.json`), to S3 with this command: `cyclops config push ports`. Then, get the URL to the ports file and add it to `config.json` under `platform.ports`.
8. Now we create our "platform stack" in CloudFormation. Go to the [CloudFormation UI](https://console.aws.amazon.com/cloudformation/home?region=us-east-1), Select "Create Stack", Enter a name ("platform"), and specify an Amazon S3 URL for the template (the S3 URL of the platform config that we just pushed). When done, click "Next".


### DNS setup

We need to setup a hosted zone for each cluster we have created.

1. Go to the [Route 53 Hosted Zones UI](https://console.aws.amazon.com/route53/home?region=us-east-1#hosted-zones:)
2. Add a new hosted zone for staging (eg: "cloud-staging.okfnlabs.org"), and one for production (eg: "cloud-staging.okfnlabs.org.").
3. Add the values of the hosted zones to your `config.json` under `services.dns.staging` and `services.dns.production`

### Cluster setup

Once we have the platform setup done, we can move on to the cluster setup.

1. Go to the [EC2 Container Service UI](https://console.aws.amazon.com/ecs/home?region=us-east-1), and first, follow the steps to "Create a task definition from sample", **if you are prompted to do so**. This is just a dummy step - we currently need to do this in order to create our own clusters.
2. Now go again to [EC2 Container Service UI](https://console.aws.amazon.com/ecs/home?region=us-east-1). You will see the full UI: it is different from when you started step 1. You will now see a "default" cluster displayed. We now want to create two more clusters: "production" and "staging" - use exactly those names (currently hardcoded in `cyclops`). These clusters will be used when we create the cluster stacks in subsequent steps.
3. You may also delete the "default" cluster that was created in step 1. This involves deleting its stack in the [CloudFormation UI](https://console.aws.amazon.com/cloudformation/home?region=us-east-1), which ensures all tasks/services, and the EC2 instance that was launched to host it, are removed.
4. Go to the [EC2 Keypair UI](https://console.aws.amazon.com/ec2/v2/home?region=us-east-1#KeyPairs:sort=keyName) and create a new keypair with the name "cloud" (can be any name but the name is important for subsequent steps). Creating the keypair will result in a .pem file download to your local machine. Add the name to your local `config.json` under `cluster.keyname`
5. Go to the [VPC UI](https://console.aws.amazon.com/vpc/home?region=us-east-1#vpcs:) and copy the "VPC ID" to `cluster.vpc` in `config.json`.
6. Go to the [VPC Subnets UI](https://console.aws.amazon.com/vpc/home?region=us-east-1#subnets:) and you will see two subnets. Copy these into an array under the `cluster.subnets` key in `config.json`
7. Once we have those essential settings in our config, we'll save our CloudFormation template for the **cluster** (`config/cluster.json`) to S3 with this command: `cyclops config push cluster`. The response to this command will be the S3 URL for the cluster config, which you will need in the next step.
8. Now we create our "cluster stacks" in CloudFormation: one for "production", and one for "staging". Go to the [CloudFormation UI](https://console.aws.amazon.com/cloudformation/home?region=us-east-1), Select "Create Stack", call it "cluster-staging", and specify an Amazon S3 URL for the template (the S3 URL of the platform config that we just pushed). Then, you will need to fill in set the `EcsClusterName` to "staging". When done, repeat the same process again for a stack called "cluster-production", and this time set the `EcsClusterName` to "production".
9. Note that other defaults can be changed here: size of cluster, size of machines used in cluster, and so on.

##### A note on autoscaling

For our use case (one compute pool serving many apps), there is no autoscaling of the cluster based on # apps deployed into the cluster. We could setup a task that does something like this in the future (scale machines of sum of deployed container memory is, for example, 70% or above of available memory). In the meantime, we have to scale the cluster via the AWS UI.

### Services setup

With platform and clusters ready, we can setup some services.

#### RDS setup

We need to setup a DB Instance for each cluster we have created.

1. Go to the [RDS UI](https://console.aws.amazon.com/rds/home?region=us-east-1)
2. Add a new DB Instance for staging and production alike: Select the Postgres backend, select "yes" to multi-AZ deployments, Select the appropriate Postgres engine version. Select a "db.r3" instance class (I chose one with 30 GB RAM), select "yes" to Multi-AZ and "Provisioned IOPS" for storage type. Select a large allocated storage (I chose 1TB) and a relevant figure for Provisioned IOPS (I chose 5000).
3. More selections: DB Instance identifier ("cloud-production", "cloud-staging"), Master Username ("cloud_production", "cloud_staging"), and password (I choose same appended with "\_01").
4. Network settings: Select our VPC. Select publicly accessible and assign the security group of the relevant cluster.
5. Then, finally, "Launch DB Instance" - and then repeat for the next cluster.
6. Add the values of the DB Instance URLs to your `config.json` under `services.db.staging` and `services.db.production`. Each of these is an object with keys for `url` (of the DB Instance), `name` (of the DB Instance), `username` (of the DB Instance user), `password` (of the DB Instance user).

#### ElasticCache setup

1. Go to the [ElasticCache UI](https://console.aws.amazon.com/elasticache/home?region=us-east-1)
2. Add a new cache cluster for staging and production alike: Select the Redis backend, and set a replication group name ("cloud-staging" or "cloud-production").

#### SES setup

SES is just like configuring any SMTP backend for mail, with the added step of approving the mail sender via the Amazon UI.

### App setup

1. by now, we have everything we need in our local config except the "app template". So, we'll save our CloudFormation template for the **app** (`config/app.json`) to S3 with this command: `cyclops config push app`. Then, get the URL for the app config from the S3 UI, which you then add to `app.template` in your local `config.json`.

2. Deploy apps with `python CkanCli.py deploy {DOCKERHUB_NAME} {APP_NAME} {ENVIRONMENT}`. EG: `python CkanCli.py deploy pwalsh/cyclops-test-base demo staging`. More on deployment flow below.

## Deployment

When the time comes to deploy an app, we already have one or many environments configured. For the purpose of demonstration, let's say we are deploying into an environment called "staging", and that we know that the "staging" environment is configured to serve apps as subdomains from "cloud-staging.okfnlabs.org".

The flow (performed by a developer for CKAN Cloud Phase 1) goes like this:

1. A request comes in to deploy an app for "Tel Aviv Municipality".
2. Consider a unique slug for this new app: `tel-aviv`
3. Create a new GitHub repository: `/ckan/tel-aviv`
4. Create a new Docker Hub repository for automated build from `github/ckan/tel-aviv`
5. Create a Dockerfile for tel-aviv that inherits from our base ckan Dockerfile
  * This file declares all env vars
  * This file declares any extra setup for this specific instance
6. Push this docker file (and any extra config files it may need) to the GitHub repo.
7. Docker Hub builds the container
  * build occurs outside of our cloud
  * provides a small safety point - Docker Hub needs to be able to successfully build the image
8. From local machine, while Docker Hub is building our image, we run a command to configure the environment for the new app that is about to enter it:
  * `cyclops deploy ckan/tel-aviv tel-aviv staging`
    * create DNS entry
    * create LB entry
    * create new database in RDS
    * create new schema in SOLR (?)
9. In a few minutes, we visit the site at "http://tel-aviv.cloud-staging.okfnlabs.org/"

This flow is around 10-15 minutes from start to live traffic. Parts of the flow can be further automated in the future, btu here we have a nice Phase I trade-off between automation and some manual steps.

## Working with Dockerfiles

All configuration for an app should be in a Dockerfile, or, in a file read by a Dockerfile when an image is built.

Keeping configuration in files, and having a clear flow for making changes to an app's configuration, are vital to having a good understand of what we actually have deployed, and as a basis for troubleshooting.

### Base Dockerfile

Every release of CKAN requires a Dockerfile. [Not this one - it has too much stuff in it](https://github.com/ckan/ckan/blob/master/Dockerfile). The Dockerfile should just have what is required to:

* Build CKAN and its direct dependencies
* Run CKAN

For CKAN Cloud and the design of our environments, that should just mean:

* Python
* Postgres-Client
* All pip-installable dependencies
* A `RUN` command that runs the server and performs any migrations or other tasks

[Here is an example](https://github.com/pwalsh/cyclops-test-base/blob/master/Dockerfile)

So, at a minimum, we'd want to have Dockerfiles per major version, but, likely, we'll want many more "snapshots":

* ckan/ckan-2.3
* ckan/ckan-2.4

and so on.

### App-specific Dockerfile

Every app we deploy into the cloud has its own Dockerfile. This file inherits from the appropriate base file, and adds all the app-specific things we need:

* Environment variables
* Additional dependencies

[Here is a Fake example for an app called "demo"](https://github.com/pwalsh/cyclops-test-demo/blob/master/Dockerfile)

### Deploy and update

Because our containers are stateless, we can create and destroy them at will.
