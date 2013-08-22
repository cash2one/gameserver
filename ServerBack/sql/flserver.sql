
DROP TABLE IF EXISTS `LOGIN`;
CREATE TABLE `LOGIN` (
		`userid` int(10) unsigned not null,
		`loginid` varchar(32) not null default '',
		`password` varchar(32) not null,
		`isused` int(10) unsigned not null,
		`isforbid` int(10) unsigned not null,
		`lastactivedate` varchar(32) ,
		PRIMARY KEY (`loginid`)
		);

insert into `LOGIN` values('1','loki','loki','1','0','');

