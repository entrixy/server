/*M!999999\- enable the sandbox mode */ 

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*M!100616 SET @OLD_NOTE_VERBOSITY=@@NOTE_VERBOSITY, NOTE_VERBOSITY=0 */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `audit_log` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `host_id` int(10) unsigned DEFAULT NULL,
  `action` varchar(64) NOT NULL,
  `target_type` varchar(32) NOT NULL,
  `target_id` int(10) unsigned DEFAULT NULL,
  `payload` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`payload`)),
  `ip` varchar(64) DEFAULT NULL,
  `ts` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `host_id` (`host_id`,`ts`),
  KEY `action` (`action`,`ts`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `call_log` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `user_key_id` int(10) unsigned NOT NULL,
  `number_id` int(10) unsigned NOT NULL,
  `ts` datetime NOT NULL,
  `status` varchar(16) NOT NULL,
  `actor` varchar(64) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `user_key_id` (`user_key_id`),
  KEY `ts` (`ts`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `device_revokes` (
  `device_id` int(11) NOT NULL,
  `guest_id` int(11) NOT NULL,
  `version` int(10) unsigned NOT NULL,
  `revoked` tinyint(4) NOT NULL DEFAULT 1,
  `sig` varchar(32) NOT NULL,
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`device_id`,`guest_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `devices` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `host_id` int(10) unsigned DEFAULT NULL,
  `device_key` varchar(64) NOT NULL,
  `secret_hash` varchar(64) NOT NULL,
  `label` varchar(128) NOT NULL DEFAULT '',
  `last_seen` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `claim_code` varchar(16) DEFAULT NULL,
  `vendor_id` int(10) unsigned DEFAULT NULL,
  `batch_id` int(10) unsigned DEFAULT NULL,
  `device_secret` varchar(64) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `device_key` (`device_key`),
  UNIQUE KEY `uq_claim` (`claim_code`),
  KEY `idx_host` (`host_id`),
  KEY `k_vendor` (`vendor_id`),
  KEY `k_batch` (`batch_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `guest_messages` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `host_id` int(10) unsigned NOT NULL,
  `user_key_id` int(10) unsigned NOT NULL,
  `cipher` mediumtext NOT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_pair` (`host_id`,`user_key_id`),
  KEY `idx_user_key` (`user_key_id`),
  KEY `idx_created` (`created_at`),
  CONSTRAINT `fk_msg_host` FOREIGN KEY (`host_id`) REFERENCES `hosts` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_msg_key` FOREIGN KEY (`user_key_id`) REFERENCES `user_keys` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `hosts` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `device_id` char(32) NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  `secret_hash` char(64) NOT NULL,
  `fcm_token` varchar(255) DEFAULT NULL,
  `created_at` datetime NOT NULL,
  `last_seen` datetime DEFAULT NULL,
  `plan_id` int(10) unsigned NOT NULL DEFAULT 1,
  `bound_device_fp` varchar(64) DEFAULT NULL,
  `bound_at` datetime DEFAULT NULL,
  `moved_at` datetime DEFAULT NULL,
  `prev_device_fp` varchar(64) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `device_id` (`device_id`),
  KEY `idx_user` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `key_invites` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `host_id` int(10) unsigned NOT NULL,
  `parent_key_id` int(10) unsigned NOT NULL,
  `code` char(22) NOT NULL,
  `number_ids` varchar(255) NOT NULL,
  `depth` tinyint(3) unsigned NOT NULL DEFAULT 0,
  `expires_at` datetime NOT NULL,
  `status` enum('new','redeemed','cancelled','expired') NOT NULL DEFAULT 'new',
  `child_key_id` int(10) unsigned DEFAULT NULL,
  `created_at` datetime NOT NULL,
  `redeemed_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `code` (`code`),
  KEY `parent_key_id` (`parent_key_id`),
  KEY `host_id` (`host_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `key_numbers` (
  `user_key_id` int(10) unsigned NOT NULL,
  `number_id` int(10) unsigned NOT NULL,
  `org_label` varchar(64) DEFAULT NULL,
  PRIMARY KEY (`user_key_id`,`number_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `numbers` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `host_id` int(10) unsigned NOT NULL,
  `type` enum('call','webhook','device','ble') NOT NULL DEFAULT 'call',
  `webhook_url` varchar(512) DEFAULT NULL,
  `webhook_secret` varchar(64) DEFAULT NULL,
  `webhook_mode` enum('phone','server') NOT NULL DEFAULT 'phone',
  `device_id` int(10) unsigned DEFAULT NULL,
  `data_cipher` text DEFAULT NULL,
  `data_cipher_updated` datetime DEFAULT NULL,
  `last_state` enum('open','closed','unknown') DEFAULT NULL,
  `last_state_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `host_id` (`host_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `org_nonces` (
  `org_id` int(10) unsigned NOT NULL,
  `nonce` char(32) NOT NULL,
  `ts` int(10) unsigned NOT NULL,
  PRIMARY KEY (`org_id`,`nonce`),
  KEY `ts` (`ts`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `org_requests` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `org_id` int(10) unsigned NOT NULL,
  `host_id` int(10) unsigned DEFAULT NULL,
  `code` char(16) NOT NULL,
  `ref` varchar(64) DEFAULT NULL,
  `sig` varchar(128) DEFAULT NULL,
  `sig_ts` int(11) DEFAULT NULL,
  `sig_nonce` char(32) DEFAULT NULL,
  `sig_body` text DEFAULT NULL,
  `status` enum('new','claimed','issued','revoked','expired') NOT NULL DEFAULT 'new',
  `user_key_id` int(10) unsigned DEFAULT NULL,
  `created_at` datetime NOT NULL,
  `expires_at` datetime NOT NULL,
  `claimed_at` datetime DEFAULT NULL,
  `issued_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `code` (`code`),
  KEY `org_id` (`org_id`,`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `orgs` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `user_id` int(10) unsigned DEFAULT NULL,
  `name` varchar(160) NOT NULL,
  `contact` varchar(160) DEFAULT NULL,
  `website` varchar(200) DEFAULT NULL,
  `domain` varchar(190) DEFAULT NULL,
  `domain_token` char(32) DEFAULT NULL,
  `pubkey` char(44) DEFAULT NULL,
  `pubkey_seen_at` datetime DEFAULT NULL,
  `domain_verified_at` datetime DEFAULT NULL,
  `about` text DEFAULT NULL,
  `volume` varchar(64) DEFAULT NULL,
  `logo_hash` char(32) DEFAULT NULL,
  `status` enum('pending','approved','rejected','active','blocked') NOT NULL DEFAULT 'active',
  `secret_hash` char(64) DEFAULT NULL,
  `callback_url` varchar(255) DEFAULT NULL,
  `created_at` datetime NOT NULL,
  `approved_at` datetime DEFAULT NULL,
  `decided_at` datetime DEFAULT NULL,
  `note` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `pending_actions` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `host_id` int(10) unsigned NOT NULL,
  `number_id` int(10) unsigned NOT NULL,
  `user_key_id` int(10) unsigned NOT NULL,
  `source` varchar(32) NOT NULL,
  `actor` varchar(64) DEFAULT NULL,
  `created_at` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `pending_host_msgs` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `host_id` int(10) unsigned NOT NULL,
  `payload` text NOT NULL,
  `created_at` datetime NOT NULL,
  `dedup_key` varchar(64) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_dedup` (`host_id`,`dedup_key`),
  KEY `host_id` (`host_id`),
  KEY `created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `pending_invites` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `ip` varchar(64) NOT NULL,
  `user_key` varchar(64) NOT NULL,
  `created_at` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `ip` (`ip`),
  KEY `created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `pending_notifications` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `kind` varchar(32) NOT NULL,
  `user_key_id` int(10) unsigned NOT NULL,
  `created_at` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `user_key_id` (`user_key_id`),
  KEY `created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `plans` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(64) NOT NULL,
  `max_numbers` int(11) NOT NULL DEFAULT 10,
  `max_keys` int(11) NOT NULL DEFAULT 20,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_keys` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `host_id` int(10) unsigned NOT NULL,
  `org_id` int(10) unsigned DEFAULT NULL,
  `parent_key_id` int(10) unsigned DEFAULT NULL,
  `delegate_depth` tinyint(3) unsigned NOT NULL DEFAULT 0,
  `guest_pub` varchar(128) DEFAULT NULL,
  `key_cipher` varchar(255) DEFAULT NULL,
  `key_hash` char(64) NOT NULL,
  `enabled` tinyint(1) NOT NULL DEFAULT 1,
  `mode` varchar(16) NOT NULL DEFAULT 'auto',
  `force_when_busy` tinyint(1) NOT NULL DEFAULT 0,
  `created_at` datetime NOT NULL,
  `expires_at` datetime DEFAULT NULL,
  `pwa_user_id` int(10) unsigned DEFAULT NULL,
  `bundle_cipher` text DEFAULT NULL,
  `bundle_cipher_updated` datetime DEFAULT NULL,
  `bound_device_fp` varchar(64) DEFAULT NULL,
  `bound_at` datetime DEFAULT NULL,
  `moved_at` datetime DEFAULT NULL,
  `prev_device_fp` varchar(64) DEFAULT NULL,
  `native_only` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `key_hash` (`key_hash`),
  KEY `host_id` (`host_id`),
  KEY `org_id` (`org_id`),
  KEY `parent_key_id` (`parent_key_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `email` varchar(255) NOT NULL,
  `name` varchar(128) DEFAULT NULL,
  `password_hash` varchar(255) NOT NULL,
  `role` varchar(24) NOT NULL DEFAULT 'user',
  `plan_id` int(11) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `reset_token` varchar(64) DEFAULT NULL,
  `reset_token_exp` datetime DEFAULT NULL,
  `avatar` varchar(64) DEFAULT NULL,
  `email_confirmed` tinyint(1) NOT NULL DEFAULT 0,
  `confirm_token` varchar(64) DEFAULT NULL,
  `sess_ver` int(10) unsigned NOT NULL DEFAULT 0,
  `confirm_sent_at` datetime DEFAULT NULL,
  `confirm_sent_count` int(11) NOT NULL DEFAULT 0,
  `reset_sent_at` datetime DEFAULT NULL,
  `reset_sent_count` int(11) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`),
  UNIQUE KEY `uq_name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*M!100616 SET NOTE_VERBOSITY=@OLD_NOTE_VERBOSITY */;


--
-- Invitations to a closed server. These tables exist in the distribution
-- only: entrixy.com is open, and there is nobody to invite there.
--
CREATE TABLE `access_invites` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `code` varchar(64) NOT NULL,
  `note` varchar(191) NOT NULL DEFAULT '',
  `uses_left` int(11) NOT NULL DEFAULT 1,
  `used_count` int(11) NOT NULL DEFAULT 0,
  `expires_at` datetime DEFAULT NULL,
  `revoked_at` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_invite_code` (`code`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `access_invite_uses` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `invite_id` int(11) NOT NULL,
  `host_id` int(11) NOT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_use_invite` (`invite_id`),
  KEY `idx_use_host` (`host_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
