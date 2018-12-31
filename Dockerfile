FROM centos:6
RUN curl -o /etc/yum.repos.d/CentOS-Base.repo http://mirrors.aliyun.com/repo/Centos-6.repo;\
curl -o /etc/yum.repos.d/mongodb-org-3.0.repo https://mirrors.aliyun.com/mongodb/yum/redhat/mongodb-org-3.0.repo;\
curl -o /etc/yum.repos.d/mono-centos6-stable.repo https://download.mono-project.com/repo/centos6-stable.repo;\
yum makecache;\
yum install -y cronie httpd mod_ssl sudo postgresql mongodb-org php compat-libtermcap uuid json-c php-ldap php-mbstring php-pdo php-pgsql php-soap php-xml php-xmlrpc;
