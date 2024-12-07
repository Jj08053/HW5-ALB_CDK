from aws_cdk import (
    Stack,
    aws_iam as iam,
    aws_ec2 as ec2,
    aws_elasticloadbalancingv2 as elbv2,
    aws_elasticloadbalancingv2_targets as elbv2_targets
)
import aws_cdk as cdk
# from aws_cdk import aws_cloudformation as cfn
from constructs import Construct

class AlbCdkStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Define InstanceType parameter
        self.instance_type_param = cdk.CfnParameter(self, 'InstanceType',
                                             type='String',
                                             description='The instance type for the instances. Must be t2.micro or t2.small',
                                             default='t2.micro')
        
        # Define KeyPair parameter
        self.key_pair_param = cdk.CfnParameter(self, 'KeyPair',
                                             type='String',
                                             description='The server key pair name for the EC2 instances')
        self.key_pair = ec2.KeyPair.from_key_pair_attributes(self, "KeyPairFormat",
                                                                key_pair_name=self.key_pair_param.value_as_string
                                                            )

        # Define InstanceType parameter
        self.ip_param = cdk.CfnParameter(self, 'YourIp',
                                             type='String',
                                             description='Your public IP address in CIDR notation (e.g., 192.168.1.1/32).')
        
        # Create a VPC. CDK by default creates and attaches internet gateway for VPC
        self.vpc = ec2.Vpc(self, "EngineeringVpc", 
                                    ip_addresses=ec2.IpAddresses.cidr("10.0.0.0/18"),
                                    subnet_configuration=[
                                       ec2.SubnetConfiguration(
                                            name='Public',
                                            subnet_type=ec2.SubnetType.PUBLIC,
                                            cidr_mask=24,
                                            map_public_ip_on_launch=True
                                        ), 
                                    ],
                                    nat_gateways = 0,
                                    availability_zones = ["us-east-1a","us-east-1b"])
        
        self.user_data = ec2.UserData.for_linux()
        self.user_data.add_commands(
            "yum update -y",
            "yum install -y git httpd php",
            "service httpd start",
            "chkconfig httpd on",
            "aws s3 cp s3://seis665-public/index.php /var/www/html/"
        )
        
        self.WebserversSG = ec2.SecurityGroup(self,"WebserversSG",
                                              vpc = self.vpc, 
                                              description="Security group for web servers",
                                              security_group_name="WebserversSG"
                                              )
        self.WebserversSG.add_ingress_rule(ec2.Peer.ipv4(self.ip_param.value_as_string),
                                                        ec2.Port.tcp(22), 
                                                        "Open port 22 from your IP")
        self.WebserversSG.add_ingress_rule(ec2.Peer.any_ipv4(),
                                                        ec2.Port.tcp(80), 
                                                        "Open port 80 from anywhere")
        
        self.s3_access_role = iam.Role(self, "S3AccessRole",
                                    assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
                                    role_name="S3AccessRole",
                                    inline_policies={
                                        "S3Policy": iam.PolicyDocument(
                                            statements=[
                                                iam.PolicyStatement(
                                                    effect=iam.Effect.ALLOW,
                                                    actions=["s3:GetObject"],
                                                    resources=["arn:aws:s3:::seis665-public/*"]
                                                )
                                            ]
                                        )
                                    }
                                )

        # Create one EC2 instance at public subnet 1 in us-east-1a
        self.web_instance_1 = ec2.Instance(self,
                                            "web1",
                                            vpc = self.vpc,
                                            instance_type = ec2.InstanceType(instance_type_identifier = self.instance_type_param.value_as_string),
                                            machine_image=ec2.MachineImage.generic_linux({"us-east-1": "ami-01cc34ab2709337aa"}),
                                            vpc_subnets=ec2.SubnetSelection(availability_zones=["us-east-1a"],
                                                                            subnet_type=ec2.SubnetType.PUBLIC),
                                            instance_name="web1",
                                            security_group=self.WebserversSG,
                                            key_pair = self.key_pair,
                                            user_data=self.user_data,
                                            role=self.s3_access_role
                                            )
        
        # Create another EC2 instance at public subnet 2 in us-east-1b
        self.web_instance_2 = ec2.Instance(self,
                                            "web2",
                                            vpc = self.vpc,
                                            instance_type = ec2.InstanceType(instance_type_identifier = self.instance_type_param.value_as_string),
                                            machine_image=ec2.MachineImage.generic_linux({"us-east-1": "ami-01cc34ab2709337aa"}),
                                            vpc_subnets=ec2.SubnetSelection(availability_zones=["us-east-1b"],
                                                                            subnet_type=ec2.SubnetType.PUBLIC),
                                            instance_name="web2",
                                            security_group=self.WebserversSG,
                                            key_pair = self.key_pair,
                                            user_data=self.user_data,
                                            role=self.s3_access_role
                                            )
        
        cdk.Tags.of(self.web_instance_1).add("Name", "web1")
        cdk.Tags.of(self.web_instance_2).add("Name", "web2")
        
        # Create an application load balancer
        self.alb = elbv2.ApplicationLoadBalancer(self, "EngineeringLB",
                                                    vpc=self.vpc,
                                                    internet_facing=True,
                                                    load_balancer_name="EngineeringLB",
                                                    security_group=self.WebserversSG,
                                                )
        
        # Create a Target Group for EC2 instances
        self.target_group = elbv2.ApplicationTargetGroup(self, "EngineeringWebservers",
                                                            vpc = self.vpc,
                                                            port=80,
                                                            protocol=elbv2.ApplicationProtocol.HTTP,
                                                            target_type=elbv2.TargetType.INSTANCE,
                                                            health_check=elbv2.HealthCheck(
                                                                enabled=True,
                                                                path="/",
                                                                interval=cdk.Duration.seconds(30),
                                                                timeout=cdk.Duration.seconds(5),
                                                                port="80",
                                                                protocol=elbv2.Protocol.HTTP,
                                                                healthy_http_codes="200",
                                                                unhealthy_threshold_count = 2
                                                            ),
                                                            target_group_name = "EngineeringWebservers")

        # Add EC2 instances to the Target Group
        self.target_group.add_target(elbv2_targets.InstanceIdTarget(self.web_instance_1.instance_id, port=80))
        self.target_group.add_target(elbv2_targets.InstanceIdTarget(self.web_instance_2.instance_id, port=80))


        # Add a listener and open up the load balancer's security group to the world.
        self.listener = self.alb.add_listener("Listener",
                                                port=80,
                                                protocol = elbv2.ApplicationProtocol.HTTP,
                                                open=True,
                                                default_target_groups=[self.target_group]
                                            )
        
        # self.listener.add_targets("WebServerTargets", targets=[self.target_group])
        
        cdk.CfnOutput(self, "WebUrl", value="http://" + self.alb.load_balancer_dns_name, 
                       description="DNS name of the Application Load Balancer")
