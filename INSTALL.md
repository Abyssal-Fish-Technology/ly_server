# ly_server 管理引擎

​	ly_server是流影的管理引擎，用于聚合分析引擎产出的威胁事件、数据节点管理、用户管理、配置管理、数据查询等。



## 安装部署

```
1. 需求系统环境
	CentOS-7-x86_64-Minimal-2009

2. 安装依赖组件
	yum install net-tools ntpdate -y
 	yum install boost -y
	yum install httpd mariadb-server -y
	yum install stunnel -y
	yum install rsync -y
	yum install MySQL-python -y
	yum install sysstat -y
	yum install python-setuptools -y	
	 
3. 安装管理引擎
	# 下载主程序部署包 ly_server_release.v1.0.0.221226.tar.gz，并解压文件
	tar -xzvf ly_server_release.v1.0.0.221226.tar.gz
	
	# 下载所附依赖环境包 ly_server_dependence.v1.0.0.221226.tar.gz
	# 解压后置于上述解压缩后生成的目录中
	tar -xzvf ly_server_dependence.v1.0.0.221226.tar.gz
	mv ly_server_dependence.v1.0.0.221226/*  ly_server_release.v1.0.0.221226/

	# 进入程序目录，执行部署脚本
	cd ly_server_release.v1.0.0.221226
	./server_deploy_new.sh
```



## 配置

#### 一、运行环境配置

```
1. 配置语言和时区
   export LANG=en_US.UTF-8
   ln -s /usr/share/zoneinfo/Asia/Shanghai /etc/localtime>/dev/null 2>&1
   ntpdate cn.pool.ntp.org

2. 关闭selinux、开启防火墙端口
   #编辑config⽂件
   vi /etc/selinux/config
   #找到配置项
   SELINUX=enforcing
   #修改配置项为
   SELINUX=disabled
   #执⾏命令，即时关闭selinux
   setenforce 0

	 systemctl restart firewalld
	 firewall-cmd --zone=public --add-port=18080/tcp --permanent
	 firewall-cmd --reload

3. 配置httpd
   # 编辑/etc/httpd/conf.d/server.conf
   Listen 18080
   <VirtualHost :18080>
      DocumentRoot "/Server/www"
      AddDefaultCharset utf-8
      <Directory "/Server/www">
          Options FollowSymLinks Includes
          XBitHack on
          AllowOverride None
          Order allow,deny
          Allow from all
          Require all granted
      </Directory>
      Alias /d/ "/Server/www/d/"
      <Directory "/Server/www/d/">
          Options ExecCGI FollowSymLinks
          SetHandler cgi-script
          AllowOverride None
          Order allow,deny
          Allow from all
          Require all granted
          RewriteEngine On
          RewriteCond %{REQUEST_FILENAME} !auth$
          RewriteRule ^(.)$ auth?auth_target=$1 [QSA,PT,L]
      </Directory>
   </VirtualHost>
   
   #重启httpd
   systemctl restart httpd

4. 配置mariadb
    mkdir -p /Server/etc
    
    #编辑/Server/etc/gl.server.cnf⽂件
    vi	/Server/etc/gl.server.cnf
    
    #添加如下内容
    [gl.server]
    default-character-set=utf8
    user=root
    database=server
    passwd=
    
    
    cp /Server/etc/gl.server.cnf /etc/my.cnf.d/

		#启动数据库
		systemctl	start	mariadb
		#初始化数据库，根据提示操作即可（⽆登录密码，拒绝⾮本地登录）
		mysql_secure_installation
		#登陆本地数据库
		mysql  -uroot
		#新建数据库server
		create	database	server;
		#选择server数据库
		use	server
		#导⼊数据
		source	/root/db.server.v1.0.0.clean.sql
		#导⼊成功后，退出
		exit
		#重启mariadb
		systemctl  restart  mariadb
		
```



#### 二、运行配置		

```	
11. 创建定时任务
    编辑/var/spool/cron/root，写入内容：
    */5 * * * * /Server/bin/config_pusher
    */5 * * * * /Server/bin/gen_event
```


