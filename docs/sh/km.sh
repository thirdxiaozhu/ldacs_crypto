=======================database============================
mysql -h 192.168.136.136 -u admin -p  
mysql -h 10.5.46.81 -u admin -p  

ALTER TABLE tb_description DEFAULT CHARACTER SET utf8mb4;
show create table root_key_pool;
select hex(encrypted_key) from root_key_pool;
CREATE TABLE IF NOT EXISTS root_key_pool(encrypted_key Blob);
select * from root_key_pool;
CREATE TABLE IF NOT EXISTS root_key_pool(key_index int primary key not null auto_increment,encrypted_key Blob NOT NULL,kek_index int not null)ENGINE=InnoDB,charset =utf8mb4, auto_increment = 1;
TRUNCATE TABLE root_key_pool;

// 密钥存储保护密钥表
CREATE TABLE IF NOT EXISTS storage_protection_key (
  key_number int NOT NULL AUTO_INCREMENT,
  encrypted_key varchar(32) DEFAULT NULL,
  kek_index int DEFAULT NULL,
  PRIMARY KEY (key_number)
) ENGINE=InnoDB, charset=utf8mb4, AUTO_INCREMENT=1;

// 密钥库
CREATE TABLE IF NOT EXISTS keystore (
    key_number INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    key_type ENUM('ROOTKEY', 'MASTERKEY', 'ENCRYPTKEY', 'INTEGITYKEY'),
    key_length TINYINT UNSIGNED,
    life_cycle_phase ENUM('PRE_OPERATIONAL','OPERATIONAL', 'POST_OPERATIONAL'),
    encrypted_key CHAR(16) NOT NULL,    
    initialization_vector CHAR(16),
    key_info_check_value CHAR(2),
    key_period INT UNSIGNED,
    usage_counter INT UNSIGNED
);




==================ssh
 sudo service ssh restart
 自启动 sudo systemctl enable ssh

 ==================磁盘管理
 df -h 查看磁盘占用状态

 =====================sgx
 apt-get install build-essential ocaml ocamlbuild automake autoconf libtool wget python-is-python3 libssl-dev git cmake perl