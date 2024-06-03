# Modis
Modis implements access layer and data struct layer for [OBKV](https://github.com/oceanbase/obkv-table-client-go), compatible with Redis protocol.


## Quick Start
Build Modis
``` bash
bash build_modis.sh
```

Create table in the OceanBase database:

``` sql
-- string
create table modis_string_table(
  db bigint not null,
  rkey varbinary(1024) not null,
  value varbinary(10240) not null,
  expire_ts timestamp(6) default null,
  primary key(db, rkey))
  TTL(expire_ts + INTERVAL 0 SECOND)
	partition by key(db, rkey) partitions 389;

-- hash
create table modis_hash_table(
  db bigint not null,
  rkey varbinary(1024) not null,
  field varbinary(10240) not null,
  value varbinary(10240) not null,
  expire_ts timestamp(6) default null,
  primary key(db, rkey, field))
  TTL(expire_ts + INTERVAL 0 SECOND)
  partition by key(db, rkey) partitions 389;

-- set
create table modis_set_table(
	  db bigint not null,
	  rkey varbinary(1024) not null,
	  member varbinary(10240) not null,
	  expire_ts timestamp(6) default null,
	  primary key(db, rkey, member))
    TTL(expire_ts + INTERVAL 0 SECOND)
	  partition by key(db, rkey) partitions 389;

-- list
create table modis_list_table(
    db bigint not null,
    rkey varbinary(1024) not null,
    idx bigint not null,
    element varbinary(10240) not null,
    expire_ts timestamp(6) default null,
    primary key(db, rkey, idx))
    TTL(expire_ts + INTERVAL 0 SECOND)
    partition by key(db, rkey) partitions 389;

-- zset
create table modis_zset_table(
  db bigint not null,
  rkey varbinary(1024) not null,
  member varbinary(10240) not null,
  score bigint not null,
  expire_ts timestamp(6) default null,
  index index_score(score) local,
  primary key(db, rkey, member))
  TTL(expire_ts + INTERVAL 0 SECOND)
  partition by key(db, rkey) partitions 389;
```

`config.yaml` file exmaple:
``` yaml
{
  "server": {
    "listen": ":8085",
    "max-connection": 1000, # limit 10000
    "password": "", # used for authentication
    "TLS": {
      "ssl-cert-file": "",
      "ssl-key-file": ""
    }
  },
  "log": {
    "filepath": "./log", # filename is fixed as modis.log
    "single-file-max-size": 256, # MB
    "max-backup-file-size": 10, # 0 is not delete
    "max-age-file-rem": 30, # 30 day
    "compress": false,
    "level": "info"
  },
  "storage": {
    "backend": "obkv",
    "obkv": {
      "config-server-url": "",
      "full-user-name": "",
      "password": "",
      "sys-user-name": "root",
      "sys-password": "",
      "connection-pool-size": 64
    }
  }
}
```

**NOTE:**
1. `config-server-url` is generated by [ConfigServer](https://ask.oceanbase.com/t/topic/35601923), which format is `config_url&database={database_name}`
2. `full-user-name`: the user for accessing obkv, which format is `user_name@tenant_name#cluster_name`
3. `passWord`: the password of user in fullUserName.
4. `sys-user-name`: `root` or `proxy`, which have privileges to access routing system view
5. `sys-password`: the password of sys user in sysUserName.

## Documentation
[TODO]

## Licencing

Modis is under [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0) licence. For details, see the [LICENSE](LICENSE) file.

## Contributing

Contributions are warmly welcomed and greatly appreciated. Here are a few ways you can contribute:

- Raise us an [Issue](https://github.com/oceanbase/modis/issues)
- Submit Pull Requests. For details, see [How to contribute](CONTRIBUTING.md).

## Support

In case you have any problems when using OceanBase Database, welcome reach out for help:

- GitHub Issue [GitHub Issue](https://github.com/oceanbase/modis/issues)
- Official forum [Official website](https://open.oceanbase.com)
- Knowledge base [Coming soon]

