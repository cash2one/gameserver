
DROP TABLE IF EXISTS `serverlist`;
CREATE TABLE `serverlist` (
		`id` int(10) unsigned NOT NULL ,
		`type` int(10) unsigned NOT NULL default '0',
		`name` varchar(32) NOT NULL default '',
		`ip` varchar(16) NOT NULL default '127.0.0.1',
		`port` int(10) unsigned NOT NULL default '0',
		`extip` varchar(16) NOT NULL default '127.0.0.1',
		`extport` int(10) unsigned NOT NULL default '0',
		`nettype` int(10) unsigned NOT NULL default '0',
		PRIMARY KEY (`id`)
		);

/* super */
insert into `serverlist` values('1','1','super server','127.0.0.1','10000','127.0.0.1','10000','0');
/* record */
insert into `serverlist` values('11','11','record server','127.0.0.1','11001','127.0.0.1','11001','0');
/* bill */
insert into `serverlist` values('12','12','bill server','127.0.0.1','12001','127.0.0.1','12001','0');
/* session */
insert into `serverlist` values('20','20','session server','127.0.0.1','20001','127.0.0.1','20001','0');
/* scene */
insert into `serverlist` values('21','21','scene server','127.0.0.1','21001','127.0.0.1','21001','0');
insert into `serverlist` values('22','21','scene server','127.0.0.1','21002','127.0.0.1','21002','0');
insert into `serverlist` values('23','21','scene server','127.0.0.1','21003','127.0.0.1','21003','0');
/* gateway */
insert into `serverlist` values('200','22','gateway server','127.0.0.1','22001','127.0.0.1','22001','0');
insert into `serverlist` values('201','22','gateway server','127.0.0.1','22002','127.0.0.1','22002','0');
insert into `serverlist` values('202','22','gateway server','127.0.0.1','22003','127.0.0.1','22003','0');


DROP TABLE IF EXISTS `supermassive`;
create table `supermassive`(
		`id` int(10) unsigned not NULL,
		`value` int(10) unsigned not null default '0',
		primary key (`id`)
		);
