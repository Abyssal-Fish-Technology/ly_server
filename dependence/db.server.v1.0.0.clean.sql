-- MySQL dump 10.14  Distrib 5.5.68-MariaDB, for Linux (x86_64)
--
-- Host: localhost    Database: server
-- ------------------------------------------------------
-- Server version	5.5.68-MariaDB

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `t_agent`
--

DROP TABLE IF EXISTS `t_agent`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `t_agent` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(40) DEFAULT '',
  `ip` varchar(20) DEFAULT '127.0.0.1',
  `creator` varchar(20) DEFAULT 'admin',
  `status` varchar(20) DEFAULT 'disconnected',
  `comment` varchar(200) DEFAULT '',
  `disabled` char(1) DEFAULT 'Y',
  PRIMARY KEY (`id`),
  UNIQUE KEY `ip` (`ip`)
) ENGINE=MyISAM AUTO_INCREMENT=2 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_agent`
--

LOCK TABLES `t_agent` WRITE;
/*!40000 ALTER TABLE `t_agent` DISABLE KEYS */;
INSERT INTO `t_agent` VALUES (1,'AnalNode 1','127.0.0.1','admin','disconnected','','N');
/*!40000 ALTER TABLE `t_agent` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `t_asset_host`
--

DROP TABLE IF EXISTS `t_asset_host`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `t_asset_host` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `devid` int(10) unsigned NOT NULL,
  `ip` varchar(50) NOT NULL,
  `port` int(10) unsigned NOT NULL,
  `host` varchar(128) NOT NULL,
  `starttime` int(10) unsigned NOT NULL,
  `endtime` int(10) unsigned NOT NULL,
  `duration` int(10) unsigned NOT NULL COMMENT 'minute',
  `is_alive` tinyint(4) NOT NULL,
  `last_hour` int(10) unsigned NOT NULL DEFAULT '0',
  `last_flows` int(10) unsigned NOT NULL DEFAULT '0',
  `flows` int(10) unsigned NOT NULL DEFAULT '0',
  `last_pkts` int(10) unsigned NOT NULL DEFAULT '0',
  `pkts` int(10) unsigned NOT NULL DEFAULT '0',
  `last_bytes` int(10) unsigned NOT NULL DEFAULT '0',
  `bytes` int(10) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`) USING BTREE,
  KEY `ip_port_host` (`ip`,`port`,`host`),
  KEY `st_et` (`starttime`,`endtime`)
) ENGINE=InnoDB DEFAULT CHARSET=gbk;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_asset_host`
--

LOCK TABLES `t_asset_host` WRITE;
/*!40000 ALTER TABLE `t_asset_host` DISABLE KEYS */;
/*!40000 ALTER TABLE `t_asset_host` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `t_asset_ip`
--

DROP TABLE IF EXISTS `t_asset_ip`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `t_asset_ip` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `devid` int(10) unsigned NOT NULL,
  `ip` varchar(50) NOT NULL,
  `starttime` int(10) unsigned NOT NULL,
  `endtime` int(10) unsigned NOT NULL,
  `duration` int(10) unsigned NOT NULL COMMENT 'minute',
  `is_alive` tinyint(4) NOT NULL,
  `last_hour` int(10) unsigned NOT NULL DEFAULT '0',
  `last_flows` int(10) unsigned NOT NULL DEFAULT '0',
  `flows` int(10) unsigned NOT NULL DEFAULT '0',
  `last_pkts` int(10) unsigned NOT NULL DEFAULT '0',
  `pkts` int(10) unsigned NOT NULL DEFAULT '0',
  `last_bytes` int(10) unsigned NOT NULL DEFAULT '0',
  `bytes` int(10) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`) USING BTREE,
  KEY `index_ip` (`ip`),
  KEY `st_et` (`starttime`,`endtime`)
) ENGINE=InnoDB DEFAULT CHARSET=gbk;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_asset_ip`
--

LOCK TABLES `t_asset_ip` WRITE;
/*!40000 ALTER TABLE `t_asset_ip` DISABLE KEYS */;
/*!40000 ALTER TABLE `t_asset_ip` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `t_asset_srv`
--

DROP TABLE IF EXISTS `t_asset_srv`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `t_asset_srv` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `devid` int(10) unsigned NOT NULL,
  `ip` varchar(50) NOT NULL,
  `port` int(10) unsigned NOT NULL,
  `protocol` int(10) unsigned NOT NULL,
  `app_proto` varchar(40) NOT NULL,
  `srv_type` varchar(40) NOT NULL,
  `srv_name` varchar(40) NOT NULL,
  `srv_version` varchar(40) NOT NULL,
  `dev_type` varchar(40) NOT NULL,
  `dev_name` varchar(80) NOT NULL,
  `dev_vendor` varchar(40) NOT NULL,
  `dev_model` varchar(20) NOT NULL,
  `os_type` varchar(40) NOT NULL,
  `os_name` varchar(40) NOT NULL,
  `os_version` varchar(40) NOT NULL,
  `midware_type` varchar(40) NOT NULL,
  `midware_name` varchar(40) NOT NULL,
  `midware_version` varchar(40) NOT NULL,
  `starttime` int(10) unsigned NOT NULL,
  `endtime` int(10) unsigned NOT NULL,
  `duration` int(10) unsigned NOT NULL COMMENT 'minute',
  `is_alive` tinyint(4) NOT NULL,
  `last_hour` int(10) unsigned NOT NULL DEFAULT '0',
  `last_req_flows` int(10) unsigned NOT NULL DEFAULT '0',
  `req_flows` int(10) unsigned NOT NULL DEFAULT '0',
  `last_res_flows` int(10) unsigned NOT NULL DEFAULT '0',
  `res_flows` int(10) unsigned NOT NULL DEFAULT '0',
  `flows` int(10) unsigned NOT NULL DEFAULT '0',
  `last_req_pkts` int(10) unsigned NOT NULL DEFAULT '0',
  `req_pkts` int(10) unsigned NOT NULL DEFAULT '0',
  `last_res_pkts` int(10) unsigned NOT NULL DEFAULT '0',
  `res_pkts` int(10) unsigned NOT NULL DEFAULT '0',
  `pkts` int(10) unsigned NOT NULL DEFAULT '0',
  `last_req_bytes` int(10) unsigned NOT NULL DEFAULT '0',
  `req_bytes` int(10) unsigned NOT NULL DEFAULT '0',
  `last_res_bytes` int(10) unsigned NOT NULL DEFAULT '0',
  `res_bytes` int(10) unsigned NOT NULL DEFAULT '0',
  `bytes` int(10) unsigned NOT NULL DEFAULT '0',
  `srv_time` bigint(20) unsigned NOT NULL DEFAULT '0',
  `dev_time` bigint(20) unsigned NOT NULL DEFAULT '0',
  `os_time` bigint(20) unsigned NOT NULL DEFAULT '0',
  `midware_time` bigint(20) unsigned NOT NULL DEFAULT '0',
  `threat_time` bigint(20) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`) USING BTREE,
  KEY `ip_port_proto` (`ip`,`port`,`protocol`),
  KEY `st_et` (`starttime`,`endtime`)
) ENGINE=InnoDB DEFAULT CHARSET=gbk;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_asset_srv`
--

LOCK TABLES `t_asset_srv` WRITE;
/*!40000 ALTER TABLE `t_asset_srv` DISABLE KEYS */;
/*!40000 ALTER TABLE `t_asset_srv` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `t_asset_url`
--

DROP TABLE IF EXISTS `t_asset_url`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `t_asset_url` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `devid` int(10) unsigned NOT NULL,
  `ip` varchar(50) NOT NULL,
  `port` int(10) NOT NULL,
  `url` varchar(256) NOT NULL,
  `retcode` set('200','201','202','203','204','205','206','207','300','301','302','303','304','305','306') DEFAULT NULL,
  `starttime` int(10) unsigned NOT NULL,
  `endtime` int(10) unsigned NOT NULL,
  `duration` int(10) unsigned NOT NULL COMMENT 'minute',
  `is_alive` tinyint(4) NOT NULL,
  `last_hour` int(10) unsigned NOT NULL DEFAULT '0',
  `last_flows` int(10) unsigned NOT NULL DEFAULT '0',
  `flows` int(10) unsigned NOT NULL DEFAULT '0',
  `last_pkts` int(10) unsigned NOT NULL DEFAULT '0',
  `pkts` int(10) unsigned NOT NULL DEFAULT '0',
  `last_bytes` int(10) unsigned NOT NULL DEFAULT '0',
  `bytes` int(10) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`) USING BTREE,
  KEY `ip_port_url` (`ip`,`port`,`url`),
  KEY `st_et` (`starttime`,`endtime`)
) ENGINE=InnoDB DEFAULT CHARSET=gbk;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_asset_url`
--

LOCK TABLES `t_asset_url` WRITE;
/*!40000 ALTER TABLE `t_asset_url` DISABLE KEYS */;
/*!40000 ALTER TABLE `t_asset_url` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `t_blacklist`
--

DROP TABLE IF EXISTS `t_blacklist`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `t_blacklist` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `ip` varchar(50) DEFAULT NULL,
  `port` int(11) DEFAULT NULL,
  `desc` varchar(200) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `i_i_p` (`ip`,`port`)
) ENGINE=MyISAM DEFAULT CHARSET=gbk;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_blacklist`
--

LOCK TABLES `t_blacklist` WRITE;
/*!40000 ALTER TABLE `t_blacklist` DISABLE KEYS */;
/*!40000 ALTER TABLE `t_blacklist` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `t_config`
--

DROP TABLE IF EXISTS `t_config`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `t_config` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(200) NOT NULL,
  `value` varchar(200) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
) ENGINE=MyISAM AUTO_INCREMENT=3 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_config`
--

LOCK TABLES `t_config` WRITE;
/*!40000 ALTER TABLE `t_config` DISABLE KEYS */;
INSERT INTO `t_config` VALUES (1,'controller_host','127.0.0.1'),(2,'controller_port','10080');
/*!40000 ALTER TABLE `t_config` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `t_darkiplist`
--

DROP TABLE IF EXISTS `t_darkiplist`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `t_darkiplist` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ip` varchar(50) DEFAULT NULL,
  `mask` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=gbk;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_darkiplist`
--

LOCK TABLES `t_darkiplist` WRITE;
/*!40000 ALTER TABLE `t_darkiplist` DISABLE KEYS */;
/*!40000 ALTER TABLE `t_darkiplist` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `t_device`
--

DROP TABLE IF EXISTS `t_device`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `t_device` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) DEFAULT '',
  `type` varchar(20) DEFAULT 'router',
  `model` varchar(100) DEFAULT '',
  `agentid` int(11) DEFAULT NULL,
  `creator` varchar(100) DEFAULT '',
  `comment` varchar(200) DEFAULT '',
  `ip` varchar(20) DEFAULT '',
  `port` int(10) unsigned DEFAULT '0',
  `disabled` char(1) DEFAULT 'N',
  `flowtype` varchar(50) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
) ENGINE=MyISAM AUTO_INCREMENT=5 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_device`
--

LOCK TABLES `t_device` WRITE;
/*!40000 ALTER TABLE `t_device` DISABLE KEYS */;
INSERT INTO `t_device` VALUES (3,'DataNode 1','router','v4',1,'admin','','127.0.0.1',9995,'N','netflow'),(4,'DataNode 2','router','v6',1,'admin','','127.0.0.1',9996,'Y','netflow');
/*!40000 ALTER TABLE `t_device` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `t_event_action`
--

DROP TABLE IF EXISTS `t_event_action`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `t_event_action` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `act` int(10) unsigned NOT NULL,
  `mail` varchar(200) NOT NULL,
  `phone` varchar(200) NOT NULL,
  `uid` varchar(200) NOT NULL,
  `desc` varchar(200) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=2 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_event_action`
--

LOCK TABLES `t_event_action` WRITE;
/*!40000 ALTER TABLE `t_event_action` DISABLE KEYS */;
INSERT INTO `t_event_action` VALUES (1,1,'mailname@mailservername.com','','','Admin mail');
/*!40000 ALTER TABLE `t_event_action` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `t_event_config_black`
--

DROP TABLE IF EXISTS `t_event_config_black`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `t_event_config_black` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `data_type` varchar(200) NOT NULL,
  `min` int(10) unsigned NOT NULL,
  `max` int(10) unsigned DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=2 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_event_config_black`
--

LOCK TABLES `t_event_config_black` WRITE;
/*!40000 ALTER TABLE `t_event_config_black` DISABLE KEYS */;
INSERT INTO `t_event_config_black` VALUES (1,'bps',1,NULL);
/*!40000 ALTER TABLE `t_event_config_black` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `t_event_config_dga`
--

DROP TABLE IF EXISTS `t_event_config_dga`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `t_event_config_dga` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `sip` varchar(200) DEFAULT NULL,
  `dip` varchar(200) DEFAULT NULL,
  `qcount` int(10) unsigned NOT NULL DEFAULT '0',
  `min` int(10) unsigned NOT NULL DEFAULT '90',
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=2 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_event_config_dga`
--

LOCK TABLES `t_event_config_dga` WRITE;
/*!40000 ALTER TABLE `t_event_config_dga` DISABLE KEYS */;
INSERT INTO `t_event_config_dga` VALUES (1,NULL,NULL,50,99);
/*!40000 ALTER TABLE `t_event_config_dga` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `t_event_config_dns`
--

DROP TABLE IF EXISTS `t_event_config_dns`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `t_event_config_dns` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ip` varchar(200) DEFAULT NULL,
  `qname` varchar(200) DEFAULT NULL,
  `qcount` int(10) unsigned NOT NULL DEFAULT '0',
  `desc` varchar(200) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=2 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_event_config_dns`
--

LOCK TABLES `t_event_config_dns` WRITE;
/*!40000 ALTER TABLE `t_event_config_dns` DISABLE KEYS */;
INSERT INTO `t_event_config_dns` VALUES (1,NULL,NULL,0,'Ti domain query');
/*!40000 ALTER TABLE `t_event_config_dns` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `t_event_config_dnstun_ai`
--

DROP TABLE IF EXISTS `t_event_config_dnstun_ai`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `t_event_config_dnstun_ai` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `sip` varchar(200) NOT NULL,
  `dip` varchar(200) NOT NULL,
  `min` int(10) unsigned NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_event_config_dnstun_ai`
--

LOCK TABLES `t_event_config_dnstun_ai` WRITE;
/*!40000 ALTER TABLE `t_event_config_dnstun_ai` DISABLE KEYS */;
/*!40000 ALTER TABLE `t_event_config_dnstun_ai` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `t_event_config_dnstunnel`
--

DROP TABLE IF EXISTS `t_event_config_dnstunnel`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `t_event_config_dnstunnel` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ip` varchar(200) DEFAULT NULL,
  `namelen` int(10) unsigned NOT NULL DEFAULT '52',
  `fqcount` int(10) unsigned NOT NULL DEFAULT '150',
  `detvalue` int(10) unsigned NOT NULL DEFAULT '5000',
  `desc` varchar(200) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=2 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_event_config_dnstunnel`
--

LOCK TABLES `t_event_config_dnstunnel` WRITE;
/*!40000 ALTER TABLE `t_event_config_dnstunnel` DISABLE KEYS */;
INSERT INTO `t_event_config_dnstunnel` VALUES (1,NULL,52,150,5000,'Dns tunnel traffic');
/*!40000 ALTER TABLE `t_event_config_dnstunnel` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `t_event_config_frn_trip`
--

DROP TABLE IF EXISTS `t_event_config_frn_trip`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `t_event_config_frn_trip` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `sip` varchar(200) DEFAULT NULL,
  `dip` varchar(200) NOT NULL,
  `min` int(10) unsigned NOT NULL DEFAULT '0',
  `desc` varchar(200) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_event_config_frn_trip`
--

LOCK TABLES `t_event_config_frn_trip` WRITE;
/*!40000 ALTER TABLE `t_event_config_frn_trip` DISABLE KEYS */;
/*!40000 ALTER TABLE `t_event_config_frn_trip` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `t_event_config_icmp_tunnel`
--

DROP TABLE IF EXISTS `t_event_config_icmp_tunnel`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `t_event_config_icmp_tunnel` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `sip` varchar(200) NOT NULL,
  `dip` varchar(200) NOT NULL,
  `IF1` int(10) unsigned NOT NULL DEFAULT '5',
  `IF2` int(10) unsigned NOT NULL DEFAULT '2',
  `IF3` int(10) unsigned NOT NULL DEFAULT '5',
  `desc` varchar(200) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=2 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_event_config_icmp_tunnel`
--

LOCK TABLES `t_event_config_icmp_tunnel` WRITE;
/*!40000 ALTER TABLE `t_event_config_icmp_tunnel` DISABLE KEYS */;
INSERT INTO `t_event_config_icmp_tunnel` VALUES (1,'','',5,2,5,'');
/*!40000 ALTER TABLE `t_event_config_icmp_tunnel` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `t_event_config_ip_scan`
--

DROP TABLE IF EXISTS `t_event_config_ip_scan`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `t_event_config_ip_scan` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `min_peerports` int(10) unsigned NOT NULL,
  `max_peerports` int(10) unsigned DEFAULT NULL,
  `sip` varchar(32) DEFAULT NULL,
  `dip` varchar(32) DEFAULT NULL,
  `protocol` varchar(32) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=2 DEFAULT CHARSET=gbk;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_event_config_ip_scan`
--

LOCK TABLES `t_event_config_ip_scan` WRITE;
/*!40000 ALTER TABLE `t_event_config_ip_scan` DISABLE KEYS */;
INSERT INTO `t_event_config_ip_scan` VALUES (1,1000,NULL,NULL,NULL,NULL);
/*!40000 ALTER TABLE `t_event_config_ip_scan` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `t_event_config_port_scan`
--

DROP TABLE IF EXISTS `t_event_config_port_scan`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `t_event_config_port_scan` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `min_peerips` int(10) unsigned NOT NULL,
  `max_peerips` int(10) unsigned DEFAULT NULL,
  `ip` varchar(32) DEFAULT NULL,
  `port` int(10) unsigned DEFAULT NULL,
  `protocol` varchar(32) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=4 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_event_config_port_scan`
--

LOCK TABLES `t_event_config_port_scan` WRITE;
/*!40000 ALTER TABLE `t_event_config_port_scan` DISABLE KEYS */;
INSERT INTO `t_event_config_port_scan` VALUES (1,1000,NULL,NULL,NULL,NULL),(2,300,NULL,NULL,22,NULL),(3,300,NULL,NULL,3389,NULL);
/*!40000 ALTER TABLE `t_event_config_port_scan` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `t_event_config_srv`
--

DROP TABLE IF EXISTS `t_event_config_srv`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `t_event_config_srv` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `min_portsessions` int(10) unsigned NOT NULL,
  `max_portsessions` int(10) unsigned DEFAULT NULL,
  `ip` varchar(32) NOT NULL,
  `port` int(10) unsigned DEFAULT NULL,
  `protocol` varchar(32) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=4 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_event_config_srv`
--

LOCK TABLES `t_event_config_srv` WRITE;
/*!40000 ALTER TABLE `t_event_config_srv` DISABLE KEYS */;
INSERT INTO `t_event_config_srv` VALUES (1,3000,NULL,'',NULL,NULL),(2,300,NULL,'',22,NULL),(3,300,NULL,'',3389,NULL);
/*!40000 ALTER TABLE `t_event_config_srv` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `t_event_config_sus`
--

DROP TABLE IF EXISTS `t_event_config_sus`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `t_event_config_sus` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `data_type` varchar(200) NOT NULL,
  `min` int(10) unsigned NOT NULL,
  `max` int(10) unsigned DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=2 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_event_config_sus`
--

LOCK TABLES `t_event_config_sus` WRITE;
/*!40000 ALTER TABLE `t_event_config_sus` DISABLE KEYS */;
INSERT INTO `t_event_config_sus` VALUES (1,'bps',1000,NULL);
/*!40000 ALTER TABLE `t_event_config_sus` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `t_event_config_threshold`
--

DROP TABLE IF EXISTS `t_event_config_threshold`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `t_event_config_threshold` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `moid` int(11) NOT NULL,
  `thres_mode` varchar(200) NOT NULL,
  `data_type` varchar(200) NOT NULL,
  `min` int(10) unsigned DEFAULT NULL,
  `max` int(10) unsigned DEFAULT NULL,
  `grep_rule` varchar(200) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_event_config_threshold`
--

LOCK TABLES `t_event_config_threshold` WRITE;
/*!40000 ALTER TABLE `t_event_config_threshold` DISABLE KEYS */;
/*!40000 ALTER TABLE `t_event_config_threshold` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `t_event_config_url_content`
--

DROP TABLE IF EXISTS `t_event_config_url_content`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `t_event_config_url_content` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `min` int(10) unsigned NOT NULL DEFAULT '0',
  `type` int(11) NOT NULL,
  `pat` varchar(400) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_event_config_url_content`
--

LOCK TABLES `t_event_config_url_content` WRITE;
/*!40000 ALTER TABLE `t_event_config_url_content` DISABLE KEYS */;
/*!40000 ALTER TABLE `t_event_config_url_content` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `t_event_data`
--

DROP TABLE IF EXISTS `t_event_data`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `t_event_data` (
  `time` int(10) unsigned NOT NULL,
  `event_id` int(11) NOT NULL,
  `type` varchar(200) NOT NULL,
  `model` int(1) unsigned NOT NULL,
  `devid` int(11) NOT NULL,
  `level` varchar(200) NOT NULL,
  `obj` varchar(200) NOT NULL,
  `thres_value` int(10) unsigned NOT NULL,
  `alarm_value` int(10) unsigned NOT NULL,
  `value_type` varchar(200) NOT NULL,
  `desc` varchar(200) NOT NULL,
  `id` int(11) NOT NULL AUTO_INCREMENT,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_event_data`
--

LOCK TABLES `t_event_data` WRITE;
/*!40000 ALTER TABLE `t_event_data` DISABLE KEYS */;
/*!40000 ALTER TABLE `t_event_data` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `t_event_data_aggre`
--

DROP TABLE IF EXISTS `t_event_data_aggre`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `t_event_data_aggre` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `event_id` int(11) NOT NULL,
  `devid` int(11) NOT NULL,
  `obj` varchar(200) NOT NULL,
  `type` varchar(200) NOT NULL,
  `model` int(1) unsigned NOT NULL,
  `level` varchar(200) NOT NULL,
  `alarm_peak` int(10) unsigned NOT NULL,
  `sub_events` int(10) unsigned NOT NULL,
  `alarm_avg` int(10) unsigned NOT NULL,
  `value_type` varchar(200) NOT NULL,
  `desc` varchar(200) NOT NULL,
  `duration` int(10) unsigned NOT NULL COMMENT 'minutes',
  `starttime` int(10) unsigned NOT NULL,
  `endtime` int(10) unsigned NOT NULL,
  `is_alive` tinyint(4) NOT NULL COMMENT '0:false, 1:true',
  `proc_status` varchar(24) NOT NULL DEFAULT 'unprocessed',
  `proc_comment` varchar(200) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `index_obj` (`obj`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_event_data_aggre`
--

LOCK TABLES `t_event_data_aggre` WRITE;
/*!40000 ALTER TABLE `t_event_data_aggre` DISABLE KEYS */;
/*!40000 ALTER TABLE `t_event_data_aggre` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `t_event_ignore`
--

DROP TABLE IF EXISTS `t_event_ignore`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `t_event_ignore` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `lip` varchar(200) DEFAULT NULL,
  `tip` varchar(200) DEFAULT NULL,
  `tport` varchar(200) DEFAULT NULL,
  `protocol` varchar(200) DEFAULT NULL,
  `domain` varchar(256) DEFAULT NULL,
  `desc` varchar(200) NOT NULL,
  `weekday` varchar(20) NOT NULL,
  `stime` varchar(20) NOT NULL,
  `etime` varchar(20) NOT NULL,
  `coverrange` varchar(20) NOT NULL DEFAULT 'within',
  `count` int(11) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_event_ignore`
--

LOCK TABLES `t_event_ignore` WRITE;
/*!40000 ALTER TABLE `t_event_ignore` DISABLE KEYS */;
/*!40000 ALTER TABLE `t_event_ignore` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `t_event_level`
--

DROP TABLE IF EXISTS `t_event_level`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `t_event_level` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `desc` varchar(200) NOT NULL,
  `profile` varchar(200) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=8 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_event_level`
--

LOCK TABLES `t_event_level` WRITE;
/*!40000 ALTER TABLE `t_event_level` DISABLE KEYS */;
INSERT INTO `t_event_level` VALUES (1,'extra_high',''),(2,'high',''),(3,'middle',''),(4,'low',''),(5,'extra_low',''),(6,'auto_tight','20:50:100:200'),(7,'auto_loose','100:500:1000:5000');
/*!40000 ALTER TABLE `t_event_level` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `t_event_list`
--

DROP TABLE IF EXISTS `t_event_list`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `t_event_list` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `type_id` int(11) NOT NULL,
  `config_id` int(11) NOT NULL,
  `level_id` int(11) NOT NULL,
  `action_id` varchar(200) NOT NULL,
  `status_id` int(11) NOT NULL,
  `desc` varchar(200) NOT NULL,
  `createtime` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `devid` int(11) DEFAULT NULL,
  `weekday` varchar(20) NOT NULL,
  `stime` varchar(20) NOT NULL,
  `etime` varchar(20) NOT NULL,
  `coverrange` varchar(20) NOT NULL DEFAULT 'within',
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=16 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_event_list`
--

LOCK TABLES `t_event_list` WRITE;
/*!40000 ALTER TABLE `t_event_list` DISABLE KEYS */;
INSERT INTO `t_event_list` VALUES (1,7,1,7,'1',1,'Dns tunnel traffic','2018-09-10 00:00:00',NULL,'0,1,2,3,4,5,6','00:00:00','23:59:59','within'),(2,5,1,1,'1',2,'Blacklist traffic bps (>1)','2018-09-10 00:00:00',NULL,'0,1,2,3,4,5,6','00:00:00','23:59:59','within'),(3,2,1,7,'1',3,'Scan peers (>1k)','2018-09-10 00:00:00',NULL,'0,1,2,3,4,5,6','00:00:00','23:59:59','within'),(4,2,2,6,'1',4,'SSH peers (>300)','2018-09-10 00:00:00',NULL,'0,1,2,3,4,5,6','00:00:00','23:59:59','within'),(5,2,3,6,'1',5,'RDP peers (>300)','2018-09-10 00:00:00',NULL,'0,1,2,3,4,5,6','00:00:00','23:59:59','within'),(6,3,1,7,'1',6,'Service sessions (>3k)','2018-09-10 00:00:00',NULL,'0,1,2,3,4,5,6','00:00:00','23:59:59','within'),(7,3,2,6,'1',7,'SSH sessions (>300)','2018-09-10 00:00:00',NULL,'0,1,2,3,4,5,6','00:00:00','23:59:59','within'),(8,3,3,6,'1',8,'RDP sessions (>300)','2018-09-10 00:00:00',NULL,'0,1,2,3,4,5,6','00:00:00','23:59:59','within'),(9,4,1,7,'1',9,'Ti domain query','2018-09-10 00:00:00',NULL,'0,1,2,3,4,5,6','00:00:00','23:59:59','within'),(10,13,1,7,'1',10,'threat','2020-10-26 08:00:00',3,'0,1,2,3,4,5,6','00:00:00','23:59:59','within'),(11,6,1,7,'1',11,'ti','2021-01-25 03:08:01',3,'0,1,2,3,4,5,6','00:00:00','23:59:59','within'),(12,15,1,7,'1',12,'mining','2021-01-25 03:08:01',3,'0,1,2,3,4,5,6','00:00:00','23:59:59','within'),(13,12,1,1,'1',13,'dga init config','2022-12-22 06:37:34',NULL,'0,1,2,3,4,5,6','00:00:00','23:59:59','within'),(14,11,1,1,'1',14,'icmp tun init config','2022-12-22 06:38:14',NULL,'0,1,2,3,4,5,6','00:00:00','23:59:59','within'),(15,8,1,1,'1',15,'ip scan init config','2022-12-22 06:38:46',NULL,'0,1,2,3,4,5,6','00:00:00','23:59:59','within');
/*!40000 ALTER TABLE `t_event_list` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `t_event_status`
--

DROP TABLE IF EXISTS `t_event_status`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `t_event_status` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `moid` int(11) DEFAULT NULL,
  `status` varchar(200) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=16 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_event_status`
--

LOCK TABLES `t_event_status` WRITE;
/*!40000 ALTER TABLE `t_event_status` DISABLE KEYS */;
INSERT INTO `t_event_status` VALUES (1,NULL,'ON'),(2,NULL,'ON'),(3,NULL,'ON'),(4,NULL,'ON'),(5,NULL,'ON'),(6,NULL,'ON'),(7,NULL,'ON'),(8,NULL,'ON'),(9,NULL,'ON'),(10,NULL,'ON'),(11,NULL,'ON'),(12,NULL,'ON'),(13,NULL,'ON'),(14,NULL,'ON'),(15,NULL,'ON');
/*!40000 ALTER TABLE `t_event_status` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `t_event_type`
--

DROP TABLE IF EXISTS `t_event_type`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `t_event_type` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `desc` varchar(200) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=16 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_event_type`
--

LOCK TABLES `t_event_type` WRITE;
/*!40000 ALTER TABLE `t_event_type` DISABLE KEYS */;
INSERT INTO `t_event_type` VALUES (1,'mo'),(2,'port_scan'),(3,'srv'),(4,'dns'),(5,'black'),(6,'ti'),(7,'dns_tun'),(8,'ip_scan'),(9,'url_content'),(10,'frn_trip'),(11,'icmp_tun'),(12,'dga'),(13,'cap'),(14,'dnstun_ai'),(15,'mining');
/*!40000 ALTER TABLE `t_event_type` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `t_internal_ip_list`
--

DROP TABLE IF EXISTS `t_internal_ip_list`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `t_internal_ip_list` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ip` varchar(200) NOT NULL,
  `desc` varchar(200) NOT NULL,
  `devid` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=5 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_internal_ip_list`
--

LOCK TABLES `t_internal_ip_list` WRITE;
/*!40000 ALTER TABLE `t_internal_ip_list` DISABLE KEYS */;
INSERT INTO `t_internal_ip_list` VALUES (1,'0.0.0.0/0','',3),(2,'2001::/16','国内段1',4),(3,'2000::/3','全球互联网段',4),(4,'2400::/12','国内段2',4);
/*!40000 ALTER TABLE `t_internal_ip_list` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `t_internal_srv_list`
--

DROP TABLE IF EXISTS `t_internal_srv_list`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `t_internal_srv_list` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ip` varchar(50) NOT NULL,
  `port` int(10) unsigned NOT NULL,
  `desc` varchar(200) NOT NULL,
  `devid` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_internal_srv_list`
--

LOCK TABLES `t_internal_srv_list` WRITE;
/*!40000 ALTER TABLE `t_internal_srv_list` DISABLE KEYS */;
/*!40000 ALTER TABLE `t_internal_srv_list` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `t_mo`
--

DROP TABLE IF EXISTS `t_mo`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `t_mo` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `moip` varchar(200) NOT NULL,
  `moport` varchar(200) NOT NULL,
  `protocol` varchar(200) NOT NULL,
  `pip` varchar(200) NOT NULL,
  `pport` varchar(200) NOT NULL,
  `modesc` varchar(200) NOT NULL,
  `tag` varchar(200) NOT NULL,
  `mogroupid` int(11) NOT NULL DEFAULT '1',
  `addtime` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `filter` varchar(1000) NOT NULL,
  `devid` int(11) DEFAULT NULL,
  `direction` varchar(10) NOT NULL DEFAULT 'ALL',
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=33 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_mo`
--

LOCK TABLES `t_mo` WRITE;
/*!40000 ALTER TABLE `t_mo` DISABLE KEYS */;
INSERT INTO `t_mo` VALUES (1,'','0','','','','Port 0 traffic','',5,'2018-09-10 00:00:00','port 0 and not proto ICMP',3,'ALL'),(2,'','22','','','','SSH traffic','',4,'2018-09-10 00:00:00','port 22',3,'ALL'),(3,'','3389','','','','RDP traffic','',4,'2018-09-10 00:00:00','port 3389',3,'ALL'),(4,'','5800','','','','VNC traffic','',4,'2018-09-10 00:00:00','port 5800',3,'ALL'),(5,'','5900','','','','VNC traffic','',4,'2018-09-10 00:00:00','port 5900',3,'ALL'),(6,'','6000','','','','X11 traffic','',4,'2018-09-10 00:00:00','port 6000',3,'ALL'),(7,'','3306','','','','MySQL/MariaDB','',4,'2018-09-10 00:00:00','port 3306',3,'ALL'),(8,'','1521','','','','Oracle traffic','',4,'2018-09-10 00:00:00','port 1521',3,'ALL'),(9,'','1433','','','','SQLServer traffic','',4,'2018-09-10 00:00:00','port 1433',3,'ALL'),(10,'','5000','','','','DB2 traffic','',4,'2018-09-10 00:00:00','port 5000',3,'ALL'),(11,'','5432','','','','psotgreSQL traffic','',4,'2018-09-10 00:00:00','port 5432',3,'ALL'),(12,'','9300','','','','Elasticsearch traffic','',4,'2018-09-10 00:00:00','port 9300',3,'ALL'),(13,'','27017','','','','MongoDB traffic','',4,'2018-09-10 00:00:00','port 27017',3,'ALL'),(14,'','6379','','','','Redis traffic','',4,'2018-09-10 00:00:00','port 6379',3,'ALL'),(15,'','11211','','','','memcached traffic','',4,'2018-09-10 00:00:00','port 11211',3,'ALL'),(16,'','80','','','','HTTP traffic','',4,'2018-09-10 00:00:00','port 80',3,'ALL'),(17,'','8080','','','','HTTP traffic','',4,'2018-09-10 00:00:00','port 8080',3,'ALL'),(18,'','443','','','','HTTPs traffic','',4,'2018-09-10 00:00:00','port 443',3,'ALL'),(19,'','25','','','','SMTP traffic','',4,'2018-09-10 00:00:00','port 25',3,'ALL'),(20,'','110','','','','POP3 traffic','',4,'2018-09-10 00:00:00','port 110',3,'ALL'),(21,'','465','','','','SMTPs/IMAP traffic','',4,'2018-09-10 00:00:00','port 465',3,'ALL'),(22,'','995','','','','POP3s traffic','',4,'2018-09-10 00:00:00','port 995',3,'ALL'),(23,'','993','','','','IMAP traffic','',4,'2018-09-10 00:00:00','port 993',3,'ALL'),(24,'','161','','','','SNMP traffic','',4,'2018-09-10 00:00:00','port 161',3,'ALL'),(25,'','162','','','','SNMP(Trap) traffic','',4,'2018-09-10 00:00:00','port 162',3,'ALL'),(26,'','514','','','','Syslog traffic','',4,'2018-09-10 00:00:00','port 514',3,'ALL'),(27,'','123','','','','NTP traffic','',4,'2018-09-10 00:00:00','port 123',3,'ALL'),(28,'','22','','','','SSH response','',3,'2018-09-10 00:00:00','src port 22',3,'OUT'),(29,'','3389','','','','RDP response','',3,'2018-09-10 00:00:00','src port 3389',3,'OUT'),(30,'','22','','','','SSH request','',2,'2018-09-10 00:00:00','dst port 22',3,'IN'),(31,'','3389','','','','RDP request','',2,'2018-09-10 00:00:00','dst port 3389',3,'IN'),(32,'','0','','','','ICMP traffic','',1,'2018-09-10 00:00:00','proto ICMP',3,'ALL');
/*!40000 ALTER TABLE `t_mo` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `t_mogroup`
--

DROP TABLE IF EXISTS `t_mogroup`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `t_mogroup` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(20) NOT NULL COMMENT 'name of mogroup',
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
) ENGINE=MyISAM AUTO_INCREMENT=6 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_mogroup`
--

LOCK TABLES `t_mogroup` WRITE;
/*!40000 ALTER TABLE `t_mogroup` DISABLE KEYS */;
INSERT INTO `t_mogroup` VALUES (1,'Unclassified'),(2,'Incoming'),(3,'Outgoing'),(4,'Observed'),(5,'Abnormal');
/*!40000 ALTER TABLE `t_mogroup` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `t_url_attack_type`
--

DROP TABLE IF EXISTS `t_url_attack_type`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `t_url_attack_type` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `desc` varchar(200) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM AUTO_INCREMENT=6 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_url_attack_type`
--

LOCK TABLES `t_url_attack_type` WRITE;
/*!40000 ALTER TABLE `t_url_attack_type` DISABLE KEYS */;
INSERT INTO `t_url_attack_type` VALUES (1,'sql_inject'),(2,'xss'),(3,'reso_explore'),(4,'visit_admin'),(5,'pull_db');
/*!40000 ALTER TABLE `t_url_attack_type` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `t_user`
--

DROP TABLE IF EXISTS `t_user`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `t_user` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(50) NOT NULL DEFAULT '',
  `pass` varchar(100) DEFAULT '',
  `lasttime` int(11) DEFAULT NULL,
  `lastip` int(10) unsigned DEFAULT NULL,
  `level` varchar(10) DEFAULT 'viewer',
  `createtime` int(11) DEFAULT NULL,
  `comment` varchar(200) DEFAULT NULL,
  `disabled` char(1) DEFAULT 'N',
  `creator` varchar(50) DEFAULT '',
  `lockedtime` bigint(20) NOT NULL DEFAULT '0',
  `lastsession` char(32) NOT NULL DEFAULT '',
  `resource` varchar(200) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
) ENGINE=MyISAM AUTO_INCREMENT=5 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_user`
--

LOCK TABLES `t_user` WRITE;
/*!40000 ALTER TABLE `t_user` DISABLE KEYS */;
INSERT INTO `t_user` VALUES (1,'admin','0b2c6435092cd5e4bafe47fdf1e92e9c',1671691008,1991902061,'sysadmin',1167580800,'','N','',0,'29cc88b25d664b6a9f0020a242dfa524','3'),(2,'operator','0b2c6435092cd5e4bafe47fdf1e92e9c',NULL,NULL,'viewer',1216486909,'','N','admin',0,'',NULL),(3,'viewer','0b2c6435092cd5e4bafe47fdf1e92e9c',NULL,NULL,'viewer',1216633669,'','N','admin',0,'',NULL),(4,'guanxingtai','9847e9a5b16b7f60e708fbb9b2d1438e',NULL,NULL,'viewer',1216633669,'','N','admin',0,'','3');
/*!40000 ALTER TABLE `t_user` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `t_user_session`
--

DROP TABLE IF EXISTS `t_user_session`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `t_user_session` (
  `sid` char(32) NOT NULL,
  `uid` int(11) NOT NULL,
  `expire_time` int(11) NOT NULL,
  PRIMARY KEY (`sid`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_user_session`
--

LOCK TABLES `t_user_session` WRITE;
/*!40000 ALTER TABLE `t_user_session` DISABLE KEYS */;
/*!40000 ALTER TABLE `t_user_session` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `t_user_session_history`
--

DROP TABLE IF EXISTS `t_user_session_history`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `t_user_session_history` (
  `sid` char(32) NOT NULL,
  `uid` int(11) NOT NULL DEFAULT '0',
  `action` char(32) NOT NULL,
  `code` smallint(6) NOT NULL,
  `time` bigint(20) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_user_session_history`
--

LOCK TABLES `t_user_session_history` WRITE;
/*!40000 ALTER TABLE `t_user_session_history` DISABLE KEYS */;
/*!40000 ALTER TABLE `t_user_session_history` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `t_whitelist`
--

DROP TABLE IF EXISTS `t_whitelist`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `t_whitelist` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `ip` varchar(50) DEFAULT NULL,
  `port` int(11) DEFAULT NULL,
  `desc` varchar(200) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `i_i_p` (`ip`,`port`)
) ENGINE=MyISAM DEFAULT CHARSET=gbk;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_whitelist`
--

LOCK TABLES `t_whitelist` WRITE;
/*!40000 ALTER TABLE `t_whitelist` DISABLE KEYS */;
/*!40000 ALTER TABLE `t_whitelist` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2022-12-22 14:44:21
