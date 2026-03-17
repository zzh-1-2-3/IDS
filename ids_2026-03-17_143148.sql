-- MySQL dump 10.13  Distrib 8.0.42, for Win64 (x86_64)
--
-- Host: 127.0.0.1    Database: ids
-- ------------------------------------------------------
-- Server version	8.0.42

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `adaptive_strategies`
--

DROP TABLE IF EXISTS `adaptive_strategies`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `adaptive_strategies` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `threat_level` varchar(20) COLLATE utf8mb4_unicode_ci NOT NULL,
  `attack_type` varchar(50) COLLATE utf8mb4_unicode_ci NOT NULL,
  `action` varchar(50) COLLATE utf8mb4_unicode_ci NOT NULL,
  `block_duration` varchar(20) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `packet_limit` int DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `ix_adaptive_strategies_id` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=9 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `adaptive_strategies`
--

/*!40000 ALTER TABLE `adaptive_strategies` DISABLE KEYS */;
INSERT INTO `adaptive_strategies` VALUES (1,'高风险攻击自动封禁','high','all','block','1h',NULL,0,'2026-03-05 22:13:32'),(2,'中风险攻击限流','medium','all','throttle',NULL,100,0,'2026-03-05 22:13:32'),(3,'低风险攻击告警','low','all','block','1h',NULL,0,'2026-03-05 22:13:32'),(7,'测试','low','PortScan','block','1h',NULL,0,'2026-03-12 18:05:37'),(8,'SSH-test','medium','BruteForce','block','1h',NULL,0,'2026-03-12 18:52:36');
/*!40000 ALTER TABLE `adaptive_strategies` ENABLE KEYS */;

--
-- Table structure for table `detection_results`
--

DROP TABLE IF EXISTS `detection_results`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `detection_results` (
  `id` int NOT NULL AUTO_INCREMENT,
  `timestamp` datetime DEFAULT CURRENT_TIMESTAMP,
  `src_ip` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `src_port` int DEFAULT NULL,
  `dst_ip` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `dst_port` int DEFAULT NULL,
  `protocol` varchar(20) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `packet_size` bigint DEFAULT NULL,
  `attack_type` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `confidence` float DEFAULT NULL,
  `threat_level` varchar(20) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `response_strategy` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `is_handled` int DEFAULT NULL,
  `details` text COLLATE utf8mb4_unicode_ci,
  PRIMARY KEY (`id`),
  KEY `ix_detection_results_id` (`id`),
  KEY `ix_detection_results_dst_ip` (`dst_ip`),
  KEY `ix_detection_results_src_ip` (`src_ip`)
) ENGINE=InnoDB AUTO_INCREMENT=115105 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `detection_results`
--

/*!40000 ALTER TABLE `detection_results` DISABLE KEYS */;
/*!40000 ALTER TABLE `detection_results` ENABLE KEYS */;

--
-- Table structure for table `executed_strategies`
--

DROP TABLE IF EXISTS `executed_strategies`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `executed_strategies` (
  `id` int NOT NULL AUTO_INCREMENT,
  `strategy_id` int DEFAULT NULL,
  `strategy_type` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `timestamp` datetime DEFAULT CURRENT_TIMESTAMP,
  `target_ip` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `action` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `annotation` text COLLATE utf8mb4_unicode_ci,
  `is_cancelled` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `ix_executed_strategies_id` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=12 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `executed_strategies`
--

/*!40000 ALTER TABLE `executed_strategies` DISABLE KEYS */;
INSERT INTO `executed_strategies` VALUES (1,4,'adaptive','2026-03-05 22:16:12','10.174.255.168','block','自适应策略: 低风险攻击告警, 攻击类型: all, 威胁级别: low, 动作: 封禁1h',0),(2,4,'adaptive','2026-03-05 22:16:12','36.155.163.51','block','自适应策略: 低风险攻击告警, 攻击类型: all, 威胁级别: low, 动作: 封禁1h',1),(3,4,'adaptive','2026-03-05 22:16:12','13.89.179.10','block','自适应策略: 低风险攻击告警, 攻击类型: all, 威胁级别: low, 动作: 封禁1h',1),(4,4,'adaptive','2026-03-05 22:16:13','111.48.166.31','block','自适应策略: 低风险攻击告警, 攻击类型: all, 威胁级别: low, 动作: 封禁1h',0),(6,7,'adaptive','2026-03-12 18:21:29','192.168.135.133','block','自适应策略: 测试, 攻击类型: PortScan, 威胁级别: low, 动作: 封禁1h',1),(7,7,'adaptive','2026-03-12 18:52:55','192.168.135.1','block','自适应策略: 测试, 攻击类型: PortScan, 威胁级别: low, 动作: 封禁1h',1),(8,8,'adaptive','2026-03-12 18:53:55','192.168.135.133','block','自适应策略: SSH-test, 攻击类型: BruteForce, 威胁级别: medium, 动作: 封禁1h',1),(9,8,'adaptive','2026-03-12 19:05:36','192.168.135.133','block','自适应策略: SSH-test, 攻击类型: BruteForce, 威胁级别: medium, 动作: 封禁1h',1),(10,8,'adaptive','2026-03-12 19:07:04','192.168.135.133','block','自适应策略: SSH-test, 攻击类型: BruteForce, 威胁级别: medium, 动作: 封禁1h',1),(11,8,'adaptive','2026-03-12 19:09:31','192.168.135.133','block','自适应策略: SSH-test, 攻击类型: BruteForce, 威胁级别: medium, 动作: 封禁1h',1);
/*!40000 ALTER TABLE `executed_strategies` ENABLE KEYS */;

--
-- Table structure for table `model_configs`
--

DROP TABLE IF EXISTS `model_configs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `model_configs` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `model_type` varchar(50) COLLATE utf8mb4_unicode_ci NOT NULL,
  `dataset_type` varchar(50) COLLATE utf8mb4_unicode_ci NOT NULL,
  `file_path` varchar(500) COLLATE utf8mb4_unicode_ci NOT NULL,
  `is_active` tinyint(1) DEFAULT NULL,
  `accuracy` float DEFAULT NULL,
  `precision_score` float DEFAULT NULL,
  `recall_score` float DEFAULT NULL,
  `f1_score` float DEFAULT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `description` text COLLATE utf8mb4_unicode_ci,
  `eval_results` json DEFAULT NULL,
  `eval_results_binary` json DEFAULT NULL,
  `eval_results_attack` json DEFAULT NULL,
  `last_eval_time` datetime DEFAULT NULL,
  `binary_accuracy` float DEFAULT NULL,
  `binary_precision` float DEFAULT NULL,
  `binary_recall` float DEFAULT NULL,
  `binary_f1` float DEFAULT NULL,
  `train_loss_history` json DEFAULT NULL,
  `val_loss_history` json DEFAULT NULL,
  `train_acc_history` json DEFAULT NULL,
  `val_acc_history` json DEFAULT NULL,
  `binary_train_loss_history` json DEFAULT NULL,
  `binary_val_loss_history` json DEFAULT NULL,
  `binary_train_acc_history` json DEFAULT NULL,
  `binary_val_acc_history` json DEFAULT NULL,
  `attack_train_loss_history` json DEFAULT NULL,
  `attack_val_loss_history` json DEFAULT NULL,
  `attack_train_acc_history` json DEFAULT NULL,
  `attack_val_acc_history` json DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `ix_model_configs_id` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=48 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `model_configs`
--

/*!40000 ALTER TABLE `model_configs` DISABLE KEYS */;
INSERT INTO `model_configs` VALUES (42,'CNN_7_cicids2017_20260309_232252','cnn','cicids2017','./saved_models\\cnn_cicids2017_46.pth',0,0.847967,0.891725,0.847967,0.851106,'2026-03-09 23:29:52','一阶段CNN模型（七分类）训练完成于 2026-03-09 23:29:52','{\"recall\": 0.8479670005892752, \"accuracy\": 0.8479670005892752, \"eval_dir\": \"C:\\\\Users\\\\lenovo\\\\Desktop\\\\03-基于深度学习的入侵检测系统网络流量分析系统IDS\\\\IDS\\\\IDS-Web\\\\backend\\\\eval_results\", \"f1_score\": 0.8511057050947036, \"precision\": 0.8917253910707202, \"pr_curve_image\": \"/eval_results/cnn_cicids2017_46_pr_curve.png\", \"roc_curve_image\": \"/eval_results/cnn_cicids2017_46_roc_curve.png\", \"confusion_matrix\": [[4171, 274, 821, 446, 16, 148, 231], [4, 388, 0, 1, 0, 0, 0], [16, 0, 1637, 1, 0, 0, 0], [40, 18, 7, 4752, 0, 6, 24], [0, 0, 0, 0, 6, 0, 1], [5, 204, 11, 4, 0, 1603, 2], [1, 0, 39, 2, 0, 0, 394]], \"classification_report\": {\"Bot\": {\"recall\": 0.9872773536895676, \"support\": 393.0, \"f1-score\": 0.6076742364917777, \"precision\": 0.43891402714932126}, \"DoS\": {\"recall\": 0.98040024757582, \"support\": 4847.0, \"f1-score\": 0.945389435989257, \"precision\": 0.9127929312331924}, \"BENIGN\": {\"recall\": 0.6829867365318487, \"support\": 6107.0, \"f1-score\": 0.8064578499613302, \"precision\": 0.9844229407599716}, \"PortScan\": {\"recall\": 0.8764352104975396, \"support\": 1829.0, \"f1-score\": 0.894032348020078, \"precision\": 0.9123505976095616}, \"accuracy\": 0.8479670005892752, \"WebAttack\": {\"recall\": 0.9036697247706422, \"support\": 436.0, \"f1-score\": 0.7242647058823528, \"precision\": 0.6042944785276073}, \"macro avg\": {\"recall\": 0.8968048595063471, \"support\": 15273.0, \"f1-score\": 0.7395617000670703, \"precision\": 0.6823424114590981}, \"BruteForce\": {\"recall\": 0.9897218863361548, \"support\": 1654.0, \"f1-score\": 0.7853202206764213, \"precision\": 0.6508946322067595}, \"Infiltration\": {\"recall\": 0.8571428571428571, \"support\": 7.0, \"f1-score\": 0.41379310344827586, \"precision\": 0.2727272727272727}, \"weighted avg\": {\"recall\": 0.8479670005892752, \"support\": 15273.0, \"f1-score\": 0.8511057050947036, \"precision\": 0.8917253910707202}}, \"confusion_matrix_image\": \"/eval_results/cnn_cicids2017_46_confusion_matrix.png\"}',NULL,NULL,'2026-03-09 23:52:53',NULL,NULL,NULL,NULL,'[0.20654722939935183, 0.11306107527735254, 0.12863341194394318, 0.09759800063808198, 0.08055520565951127, 0.05965114133076083, 0.04913890480695648, 0.05302831854795021, 0.03955919067122984, 0.05380943372497389, 0.03393599820236759, 0.04130206002027052, 0.042121943508006576, 0.06420353202349696]','[0.05676549381298966, 0.04873824281117854, 0.04516107327180568, 0.04903357301850952, 0.033599249366402545, 0.0396434556294528, 0.05391158949814755, 0.03578535670349686, 0.026494557195441436, 0.03452614921584856, 0.02776638115048865, 0.036423393147544184, 0.02740206357976248, 0.032542493675079845]','[0.7340688481118331, 0.7866134127776595, 0.7923425709187932, 0.8009199391072335, 0.8012309505491807, 0.811396113993878, 0.8285672193940188, 0.8236401433926438, 0.8297621580920267, 0.8382740501874253, 0.8335597714884353, 0.8344109606979752, 0.8444942790263705, 0.8367353620009494]','[0.8166044653964513, 0.8116283637792182, 0.8014142604596346, 0.8164735153538925, 0.8433837490997185, 0.8071105873109409, 0.7595757218621096, 0.8234793426307864, 0.8479670005892752, 0.7657958488836509, 0.8387350225888823, 0.8647286060367969, 0.8862044130164343, 0.850324101355333]',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(45,'CNN_2_cicids2017_20260310_002601','CNN_2','cicids2017','./saved_models\\binary_cicids2017_49.pth',0,0.967917,NULL,NULL,NULL,'2026-03-10 00:39:10','单阶段CNN（二分类）训练完成于 2026-03-10 00:39:10','{\"recall\": 0.9707326654881164, \"success\": true, \"accuracy\": 0.9707326654881164, \"eval_dir\": \"C:\\\\Users\\\\lenovo\\\\Desktop\\\\03-基于深度学习的入侵检测系统网络流量分析系统IDS\\\\IDS\\\\IDS-Web\\\\backend\\\\eval_results\", \"f1_score\": 0.970631737667084, \"precision\": 0.9710066299566416, \"model_type\": \"binary\", \"pr_curve_image\": \"/eval_results/binary_cicids2017_49_pr_curve.png\", \"roc_curve_image\": \"/eval_results/binary_cicids2017_49_roc_curve.png\", \"confusion_matrix\": [[5767, 340], [107, 9059]], \"classification_report\": {\"accuracy\": 0.9707326654881164, \"macro avg\": {\"recall\": 0.9663263034042592, \"support\": 15273.0, \"f1-score\": 0.9693066809952458, \"precision\": 0.9728050361996}, \"weighted avg\": {\"recall\": 0.9707326654881164, \"support\": 15273.0, \"f1-score\": 0.970631737667084, \"precision\": 0.9710066299566416}, \"异常(Attack)\": {\"recall\": 0.9883264237399084, \"support\": 9166.0, \"f1-score\": 0.9759224346889308, \"precision\": 0.9638259389296734}, \"正常(BENIGN)\": {\"recall\": 0.9443261830686098, \"support\": 6107.0, \"f1-score\": 0.9626909273015608, \"precision\": 0.9817841334695268}}, \"confusion_matrix_image\": \"/eval_results/binary_cicids2017_49_confusion_matrix.png\"}',NULL,NULL,'2026-03-10 00:40:05',0.970733,0.971007,0.970733,0.970632,'[0.2663144561083895, 0.1971889032566456, 0.17344860282991129, 0.15631070820185491, 0.14322291217864236, 0.13339507944947895, 0.12660198435239783, 0.1201739686092558, 0.11571130240473416, 0.1091743111268928, 0.10726904946157503, 0.10592802023290916, 0.10297460258904056, 0.09813785544917045, 0.098223218037612, 0.09639855881636757, 0.09318717955709746, 0.09279150450244988, 0.0919474781750802, 0.09023749673768132, 0.08909382155732398, 0.08711448877194188, 0.08668738032157353, 0.08634795735276223, 0.08436879143234718, 0.08330053383872098, 0.08379209488403451, 0.08364781383500916, 0.08317176545804507, 0.08135886003065006]','[0.1931975858994226, 0.1591212751564222, 0.14008853950251815, 0.11543599906366092, 0.11271610563677148, 0.10697872190691902, 0.09911664117342056, 0.09474373419941008, 0.09313582112795712, 0.09108468641374004, 0.08544273151561997, 0.08587969550535454, 0.0877694747159057, 0.08403669968384005, 0.08070441560157154, 0.07991936413480624, 0.0785749989112265, 0.0797320741979342, 0.07515702064323541, 0.0747325915114191, 0.07353462440142898, 0.07704720994378209, 0.07507713042003993, 0.07638533440411407, 0.07328233523063221, 0.07662745627837378, 0.07195160479272567, 0.07275744201197751, 0.07151553713666747, 0.07287732203379015]','[0.8846802311306085, 0.9180730385817878, 0.9283036781195266, 0.9359152739356044, 0.94172627719304, 0.945507521566188, 0.9471935309620076, 0.95072923998625, 0.95200602380056, 0.9551325072432928, 0.9556726850108854, 0.9569330998019348, 0.9573750634299651, 0.9598304169190224, 0.9599777381283658, 0.9595194054770751, 0.961483688268321, 0.9613691051054984, 0.96272773403611, 0.962253032361559, 0.9638080895712952, 0.963709875431733, 0.9643318983156276, 0.9646756478040956, 0.9656086821299372, 0.9657068962694996, 0.9659033245486242, 0.9647411238971372, 0.965985169664926, 0.9659688006416656]','[0.9203823741242716, 0.9377987297845872, 0.9410070058272768, 0.9482747331892882, 0.9510901591043016, 0.9577031362535192, 0.960060237019577, 0.9630066129771492, 0.9613042624238852, 0.9608459372749296, 0.9641196883388988, 0.9635304131473844, 0.9637923132325018, 0.9639232632750606, 0.964839913572972, 0.966214889019839, 0.9655601388070452, 0.966738689190074, 0.9671315393177504, 0.9683755647220584, 0.967262489360309, 0.9668041642113534, 0.9685065147646172, 0.9688993648922936, 0.9685065147646172, 0.9697505401689256, 0.9692267399986904, 0.968441039743338, 0.9707326654881164, 0.9679172395731028]',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(47,'two_stage_cicids2017_20260310_005415','two_stage','cicids2017','./saved_models\\binary_cicids2017_51.pth',0,0.948069,0.963942,0.948069,0.952434,'2026-03-10 01:12:21','两阶段混合模型训练完成于 2026-03-10 01:12:21','{\"recall\": 0.948068950469125, \"success\": true, \"accuracy\": 0.948068950469125, \"eval_dir\": \"C:\\\\Users\\\\lenovo\\\\Desktop\\\\03-基于深度学习的入侵检测系统网络流量分析系统IDS\\\\IDS\\\\IDS-Web\\\\backend\\\\eval_results\", \"f1_score\": 0.9524336701903456, \"precision\": 0.9639424185095564, \"model_type\": \"two_stage\", \"attack_results\": {\"recall\": 0.948068950469125, \"accuracy\": 0.948068950469125, \"f1_score\": 0.9524336701903456, \"precision\": 0.9639424185095564, \"pr_curve_image\": \"/eval_results/binary_cicids2017_51_attack_pr_curve.png\", \"roc_curve_image\": \"/eval_results/binary_cicids2017_51_attack_roc_curve.png\", \"confusion_matrix\": [[384, 1, 4, 4, 0, 0], [0, 1652, 2, 0, 0, 0], [35, 8, 4682, 31, 6, 85], [0, 0, 0, 6, 0, 1], [234, 15, 7, 0, 1571, 2], [0, 39, 2, 0, 0, 395]], \"classification_report\": {\"Bot\": {\"recall\": 0.9770992366412212, \"support\": 393.0, \"f1-score\": 0.7342256214149139, \"precision\": 0.5880551301684533}, \"DoS\": {\"recall\": 0.9659583247369506, \"support\": 4847.0, \"f1-score\": 0.9811399832355406, \"precision\": 0.9968064722163082}, \"PortScan\": {\"recall\": 0.8589393110989612, \"support\": 1829.0, \"f1-score\": 0.9224897240164416, \"precision\": 0.9961953075459734}, \"accuracy\": 0.948068950469125, \"WebAttack\": {\"recall\": 0.9059633027522936, \"support\": 436.0, \"f1-score\": 0.8596300326441785, \"precision\": 0.8178053830227743}, \"macro avg\": {\"recall\": 0.9273156404215798, \"support\": 9166.0, \"f1-score\": 0.7880319670652524, \"precision\": 0.7514115104150987}, \"BruteForce\": {\"recall\": 0.9987908101571948, \"support\": 1654.0, \"f1-score\": 0.9807064410804394, \"precision\": 0.963265306122449}, \"Infiltration\": {\"recall\": 0.8571428571428571, \"support\": 7.0, \"f1-score\": 0.25, \"precision\": 0.14634146341463414}, \"weighted avg\": {\"recall\": 0.948068950469125, \"support\": 9166.0, \"f1-score\": 0.9524336701903456, \"precision\": 0.9639424185095564}}, \"confusion_matrix_image\": \"/eval_results/binary_cicids2017_51_attack_confusion_matrix.png\"}, \"binary_results\": {\"recall\": 0.9706017154455576, \"accuracy\": 0.9706017154455576, \"f1_score\": 0.9704899492394916, \"precision\": 0.9709487913907182, \"pr_curve_image\": \"/eval_results/binary_cicids2017_51_binary_pr_curve.png\", \"roc_curve_image\": \"/eval_results/binary_cicids2017_51_binary_roc_curve.png\", \"confusion_matrix\": [[5755, 352], [97, 9069]], \"classification_report\": {\"accuracy\": 0.9706017154455576, \"macro avg\": {\"recall\": 0.9658893184997016, \"support\": 15273.0, \"f1-score\": 0.969149193065547, \"precision\": 0.973030566520614}, \"weighted avg\": {\"recall\": 0.9706017154455576, \"support\": 15273.0, \"f1-score\": 0.9704899492394916, \"precision\": 0.9709487913907182}, \"异常(Attack)\": {\"recall\": 0.9894174121754308, \"support\": 9166.0, \"f1-score\": 0.9758433313606284, \"precision\": 0.9626366627746524}, \"正常(BENIGN)\": {\"recall\": 0.9423612248239724, \"support\": 6107.0, \"f1-score\": 0.9624550547704656, \"precision\": 0.9834244702665756}}, \"confusion_matrix_image\": \"/eval_results/binary_cicids2017_51_binary_confusion_matrix.png\"}}','{\"recall\": 0.9706017154455576, \"accuracy\": 0.9706017154455576, \"f1_score\": 0.9704899492394916, \"precision\": 0.9709487913907182, \"pr_curve_image\": \"/eval_results/binary_cicids2017_51_binary_pr_curve.png\", \"roc_curve_image\": \"/eval_results/binary_cicids2017_51_binary_roc_curve.png\", \"confusion_matrix\": [[5755, 352], [97, 9069]], \"classification_report\": {\"accuracy\": 0.9706017154455576, \"macro avg\": {\"recall\": 0.9658893184997016, \"support\": 15273.0, \"f1-score\": 0.969149193065547, \"precision\": 0.973030566520614}, \"weighted avg\": {\"recall\": 0.9706017154455576, \"support\": 15273.0, \"f1-score\": 0.9704899492394916, \"precision\": 0.9709487913907182}, \"异常(Attack)\": {\"recall\": 0.9894174121754308, \"support\": 9166.0, \"f1-score\": 0.9758433313606284, \"precision\": 0.9626366627746524}, \"正常(BENIGN)\": {\"recall\": 0.9423612248239724, \"support\": 6107.0, \"f1-score\": 0.9624550547704656, \"precision\": 0.9834244702665756}}, \"confusion_matrix_image\": \"/eval_results/binary_cicids2017_51_binary_confusion_matrix.png\"}','{\"recall\": 0.948068950469125, \"accuracy\": 0.948068950469125, \"f1_score\": 0.9524336701903456, \"precision\": 0.9639424185095564, \"pr_curve_image\": \"/eval_results/binary_cicids2017_51_attack_pr_curve.png\", \"roc_curve_image\": \"/eval_results/binary_cicids2017_51_attack_roc_curve.png\", \"confusion_matrix\": [[384, 1, 4, 4, 0, 0], [0, 1652, 2, 0, 0, 0], [35, 8, 4682, 31, 6, 85], [0, 0, 0, 6, 0, 1], [234, 15, 7, 0, 1571, 2], [0, 39, 2, 0, 0, 395]], \"classification_report\": {\"Bot\": {\"recall\": 0.9770992366412212, \"support\": 393.0, \"f1-score\": 0.7342256214149139, \"precision\": 0.5880551301684533}, \"DoS\": {\"recall\": 0.9659583247369506, \"support\": 4847.0, \"f1-score\": 0.9811399832355406, \"precision\": 0.9968064722163082}, \"PortScan\": {\"recall\": 0.8589393110989612, \"support\": 1829.0, \"f1-score\": 0.9224897240164416, \"precision\": 0.9961953075459734}, \"accuracy\": 0.948068950469125, \"WebAttack\": {\"recall\": 0.9059633027522936, \"support\": 436.0, \"f1-score\": 0.8596300326441785, \"precision\": 0.8178053830227743}, \"macro avg\": {\"recall\": 0.9273156404215798, \"support\": 9166.0, \"f1-score\": 0.7880319670652524, \"precision\": 0.7514115104150987}, \"BruteForce\": {\"recall\": 0.9987908101571948, \"support\": 1654.0, \"f1-score\": 0.9807064410804394, \"precision\": 0.963265306122449}, \"Infiltration\": {\"recall\": 0.8571428571428571, \"support\": 7.0, \"f1-score\": 0.25, \"precision\": 0.14634146341463414}, \"weighted avg\": {\"recall\": 0.948068950469125, \"support\": 9166.0, \"f1-score\": 0.9524336701903456, \"precision\": 0.9639424185095564}}, \"confusion_matrix_image\": \"/eval_results/binary_cicids2017_51_attack_confusion_matrix.png\"}','2026-03-10 01:13:19',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,'[0.26907636188270045, 0.1967863167701695, 0.1739627876899835, 0.15666753580612233, 0.14507913389074958, 0.13829884542836565, 0.12849072018919278, 0.12304732143772588, 0.11708909348079025, 0.11288123072149608, 0.11045727614512216, 0.1065417499365328, 0.10349598055120728, 0.10098797951100788, 0.09892439462688564, 0.09616020759891268, 0.09365861063077296, 0.0931805908654107, 0.09182592846506972, 0.0901444554525272, 0.0884145270665404, 0.08652275953738767, 0.086630154253067, 0.08424401119851661, 0.0843013338024474, 0.08494702614900557, 0.08170725209167563, 0.08296971961591726, 0.08126656231828126, 0.07950709137589755]','[0.18519510179104384, 0.1545004469175388, 0.1418469857775977, 0.12838617934805935, 0.11959840413403716, 0.11095556096223032, 0.10355927385884948, 0.10296317289131476, 0.09351481437772866, 0.09823812587055104, 0.08973602962232032, 0.08626993493651591, 0.08266552750713689, 0.0829693824655277, 0.0809453211872082, 0.0817169205504582, 0.08098560223654805, 0.0810023441126318, 0.07654453750270715, 0.0786081575674833, 0.07538244981973131, 0.07770240649650227, 0.07419578141911454, 0.07615323843536775, 0.072726289620287, 0.07174469969407136, 0.07124830375736568, 0.07278285043433982, 0.07309387686730001, 0.07178147319295251]','[0.8840745772699743, 0.9180075624887464, 0.9284182612823492, 0.9366027729125403, 0.941218837471968, 0.9441652616588369, 0.9477828157993812, 0.9506146568234274, 0.9518587025912164, 0.9541176278011492, 0.95415036584767, 0.9560655415691346, 0.9582098836162446, 0.9586845852907956, 0.9592411320816489, 0.9605997610122604, 0.9613854741287589, 0.9622857704080796, 0.9624003535709024, 0.9627441030593704, 0.9641027319899822, 0.9646592787808352, 0.9652485636182088, 0.9647247548738768, 0.965985169664926, 0.9649702902227824, 0.9663452881766544, 0.9663943952464356, 0.9669018349675076, 0.9668036208279452]','[0.9184835985071697, 0.929876252209782, 0.939304655274013, 0.9442152818699666, 0.9524651345511688, 0.9522032344660512, 0.956982911019446, 0.953709159955477, 0.9615661625090028, 0.9624173377856348, 0.9644470634452956, 0.9634649381261048, 0.9664767891049564, 0.9641196883388988, 0.9651672886793689, 0.9655601388070452, 0.966738689190074, 0.9666732141687946, 0.96929221501997, 0.966214889019839, 0.9680481896156616, 0.9679172395731028, 0.9683100897007793, 0.968964839913573, 0.9690957899561318, 0.9698160151902048, 0.9706017154455576, 0.9683100897007793, 0.9685719897858966, 0.9695541151050874]','[0.06073153790885394, 0.01594539916273175, 0.006881258798726097, 0.0034994768008067465, 0.007107355187345278, 0.005326327612607291, 0.002358151069493049, 0.0021629861342514368, 0.01095541570883994, 0.003675502094912624, 0.003257337666189804]','[0.014442801937534716, 0.006396089816168928, 0.006468982345461549, 0.003677667104460286, 0.009673444103979866, 0.003607735854594587, 0.004026091202163216, 0.004335661478911766, 0.004238956506702628, 0.004912540656798989, 0.005266382906050865]','[0.8549609992908962, 0.9092892598047236, 0.925080456008291, 0.9384988817978508, 0.9298532700594556, 0.9359079255986472, 0.9409807451044564, 0.9437626138657068, 0.9244804450990018, 0.9396170839469808, 0.9402989145257188]','[0.948941741217543, 0.9511237180885884, 0.940868426794676, 0.8926467379445778, 0.937922758018765, 0.948068950469125, 0.9398865372027057, 0.9597425267292168, 0.948941741217543, 0.9571241544839624, 0.9533056949596336]');
/*!40000 ALTER TABLE `model_configs` ENABLE KEYS */;

--
-- Table structure for table `response_strategies`
--

DROP TABLE IF EXISTS `response_strategies`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `response_strategies` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `strategy_type` varchar(50) COLLATE utf8mb4_unicode_ci NOT NULL,
  `direction` varchar(20) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `ip_range` text COLLATE utf8mb4_unicode_ci,
  `port_range` text COLLATE utf8mb4_unicode_ci,
  `packet_limit` int DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT NULL,
  `is_executed` tinyint(1) DEFAULT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime DEFAULT NULL,
  `command_windows` text COLLATE utf8mb4_unicode_ci,
  `command_linux` text COLLATE utf8mb4_unicode_ci,
  PRIMARY KEY (`id`),
  KEY `ix_response_strategies_id` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `response_strategies`
--

/*!40000 ALTER TABLE `response_strategies` DISABLE KEYS */;
/*!40000 ALTER TABLE `response_strategies` ENABLE KEYS */;

--
-- Table structure for table `traffic`
--

DROP TABLE IF EXISTS `traffic`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `traffic` (
  `id` int NOT NULL AUTO_INCREMENT,
  `timestamp` datetime DEFAULT CURRENT_TIMESTAMP,
  `src_ip` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `src_port` int DEFAULT NULL,
  `dst_ip` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `dst_port` int DEFAULT NULL,
  `protocol` varchar(20) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `packet_size` bigint DEFAULT NULL,
  `flow_duration` float DEFAULT NULL,
  `status` varchar(20) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `attack_type` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `confidence` float DEFAULT NULL,
  `fwd_packets` int DEFAULT NULL,
  `bwd_packets` int DEFAULT NULL,
  `fwd_bytes` bigint DEFAULT NULL,
  `bwd_bytes` bigint DEFAULT NULL,
  `fwd_pkt_len_max` float DEFAULT NULL,
  `fwd_pkt_len_min` float DEFAULT NULL,
  `fwd_pkt_len_mean` float DEFAULT NULL,
  `bwd_pkt_len_max` float DEFAULT NULL,
  `bwd_pkt_len_min` float DEFAULT NULL,
  `bwd_pkt_len_mean` float DEFAULT NULL,
  `flow_bytes_s` float DEFAULT NULL,
  `flow_packets_s` float DEFAULT NULL,
  `fwd_header_len` int DEFAULT NULL,
  `bwd_header_len` int DEFAULT NULL,
  `fwd_packets_s` float DEFAULT NULL,
  `bwd_packets_s` float DEFAULT NULL,
  `min_pkt_len` float DEFAULT NULL,
  `max_pkt_len` float DEFAULT NULL,
  `pkt_len_mean` float DEFAULT NULL,
  `pkt_len_std` float DEFAULT NULL,
  `pkt_len_var` float DEFAULT NULL,
  `fwd_iat_mean` float DEFAULT NULL,
  `bwd_iat_mean` float DEFAULT NULL,
  `active_mean` float DEFAULT NULL,
  `idle_mean` float DEFAULT NULL,
  `min_idle` float DEFAULT NULL,
  `max_idle` float DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `ix_traffic_dst_ip` (`dst_ip`),
  KEY `ix_traffic_src_ip` (`src_ip`),
  KEY `ix_traffic_id` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=115109 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `traffic`
--

/*!40000 ALTER TABLE `traffic` DISABLE KEYS */;
/*!40000 ALTER TABLE `traffic` ENABLE KEYS */;

--
-- Table structure for table `training_history`
--

DROP TABLE IF EXISTS `training_history`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `training_history` (
  `id` int NOT NULL AUTO_INCREMENT,
  `model_name` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `model_type` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `dataset_type` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `batch_size` int DEFAULT NULL,
  `epochs` int DEFAULT NULL,
  `learning_rate` float DEFAULT NULL,
  `hidden_dim` int DEFAULT NULL,
  `num_layers` int DEFAULT NULL,
  `use_cuda` tinyint(1) DEFAULT NULL,
  `status` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `progress` int DEFAULT NULL,
  `loss` float DEFAULT NULL,
  `accuracy` float DEFAULT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `completed_at` datetime DEFAULT NULL,
  `train_loss_history` json DEFAULT NULL,
  `val_loss_history` json DEFAULT NULL,
  `train_acc_history` json DEFAULT NULL,
  `val_acc_history` json DEFAULT NULL,
  `binary_train_loss_history` json DEFAULT NULL,
  `binary_val_loss_history` json DEFAULT NULL,
  `binary_train_acc_history` json DEFAULT NULL,
  `binary_val_acc_history` json DEFAULT NULL,
  `attack_train_loss_history` json DEFAULT NULL,
  `attack_val_loss_history` json DEFAULT NULL,
  `attack_train_acc_history` json DEFAULT NULL,
  `attack_val_acc_history` json DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `ix_training_history_id` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=52 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `training_history`
--

/*!40000 ALTER TABLE `training_history` DISABLE KEYS */;
INSERT INTO `training_history` VALUES (13,'two_stage_cicids2017_20260306_140437','two_stage','cicids2017',64,10,0.001,128,2,1,'completed',100,0.00301354,0.948605,'2026-03-06 14:04:37','2026-03-06 14:09:30',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(14,'binary_cicids2017_20260306_141047','binary','cicids2017',64,10,0.001,128,2,1,'completed',100,0.0950172,0.959954,'2026-03-06 14:10:47','2026-03-06 14:14:24',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(15,'binary_cicids2017_20260306_142119','binary','cicids2017',64,10,0.001,128,2,1,'completed',100,0.0926908,0.959624,'2026-03-06 14:21:19','2026-03-06 14:24:51',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(16,'binary_cicids2017_20260306_142909','binary','cicids2017',64,5,0.001,128,2,1,'completed',100,0.109258,0.954893,'2026-03-06 14:29:09','2026-03-06 14:30:43',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(17,'two_stage_custom_20260306_154656','two_stage','custom',64,30,0.001,128,2,1,'completed',100,0.0098675,0.977978,'2026-03-06 15:46:56','2026-03-06 15:47:50',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(18,'binary_cicids2017_20260306_160102','binary','cicids2017',64,1,0.001,128,2,1,'completed',100,0.164112,0.92205,'2026-03-06 16:01:02','2026-03-06 16:01:21',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(19,'binary_cicids2017_20260306_160219','binary','cicids2017',64,2,0.001,128,2,1,'completed',100,0.135271,0.940019,'2026-03-06 16:02:19','2026-03-06 16:02:58',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(20,'binary_custom_20260306_160906','binary','custom',64,30,0.001,128,2,1,'completed',100,0.358927,0.978453,'2026-03-06 16:09:06','2026-03-06 16:09:22',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(21,'two_stage_custom_20260306_161107','two_stage','custom',64,30,0.001,128,2,1,'completed',100,0.0108145,0.977978,'2026-03-06 16:11:07','2026-03-06 16:12:01',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(22,'two_stage_cicids2017_20260306_161833','two_stage','cicids2017',64,2,0.001,128,2,1,'completed',100,0.00442814,0.980347,'2026-03-06 16:18:33','2026-03-06 16:20:06',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(23,'two_stage_custom_20260306_162521','two_stage','custom',64,10,0.001,128,2,1,'completed',100,0.000000215273,1,'2026-03-06 16:25:21','2026-03-06 16:25:25',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(24,'two_stage_custom_20260306_162853','two_stage','custom',64,10,0.001,128,2,1,'completed',100,0.0000000316322,1,'2026-03-06 16:28:53','2026-03-06 16:29:02',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(25,'two_stage_custom_20260306_163055','two_stage','custom',64,10,0.001,128,2,1,'completed',100,0.00000347432,1,'2026-03-06 16:30:55','2026-03-06 16:31:02',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(26,'two_stage_cicids2017_20260306_163225','two_stage','cicids2017',64,2,0.001,128,2,1,'completed',100,0.00801218,0.96491,'2026-03-06 16:32:25','2026-03-06 16:33:50',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(27,'binary_cicids2017_20260306_164551','binary','cicids2017',64,10,0.001,128,2,1,'completed',100,0.0885905,0.964828,'2026-03-06 16:45:51','2026-03-06 16:51:21',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(28,'two_stage_cicids2017_20260306_165129','two_stage','cicids2017',64,10,0.001,128,2,1,'completed',100,0.00519159,0.985446,'2026-03-06 16:51:29','2026-03-06 16:57:56',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(29,'cnn_cicids2017_20260306_170522','cnn','cicids2017',64,10,0.001,128,2,1,'completed',100,0.0795483,0.850095,'2026-03-06 17:05:22','2026-03-06 17:09:41',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(30,'binary_cicids2017_20260306_180721','binary','cicids2017',64,1,0.001,128,2,1,'completed',100,0.184452,0.924968,'2026-03-06 18:07:21','2026-03-06 18:07:55',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(31,'CNN_7_cicids2017_20260306_185632','CNN_7','cicids2017',64,10,0.001,128,2,1,'completed',100,0.0319625,0.859789,'2026-03-06 18:56:32','2026-03-06 19:02:25',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(32,'CNN_2_cicids2017_20260306_191329','CNN_2','cicids2017',64,10,0.001,128,2,1,'completed',100,0.102671,0.957125,'2026-03-06 19:13:29','2026-03-06 19:19:31',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(33,'CNN_2_cicids2017_20260309_131956','CNN_2','cicids2017',64,10,0.001,128,2,1,'completed',100,0.11462,0.939912,'2026-03-09 13:19:56','2026-03-09 13:20:38',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(34,'two_stage_cicids2017_20260309_135810','two_stage','cicids2017',64,30,0.001,128,2,1,'completed',100,0.00142303,0.98135,'2026-03-09 13:58:10','2026-03-09 13:59:17',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(35,'CNN_2_custom_20260309_140254','CNN_2','custom',64,30,0.001,128,2,1,'completed',100,0.01996,0.997399,'2026-03-09 14:02:54','2026-03-09 14:03:20',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(36,'two_stage_cicids2017_20260309_140852','two_stage','cicids2017',64,10,0.001,128,2,1,'completed',100,0.00133143,0.98135,'2026-03-09 14:08:52','2026-03-09 14:09:39',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(37,'CNN_2_cicids2017_20260309_141345','CNN_2','cicids2017',64,10,0.001,128,2,1,'completed',100,0.0886902,0.960044,'2026-03-09 14:13:45','2026-03-09 14:16:34',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(38,'two_stage_cicids2017_20260309_142626','two_stage','cicids2017',64,30,0.001,128,2,1,'completed',100,0.00140039,0.957754,'2026-03-09 14:26:26','2026-03-09 14:38:09',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(39,'two_stage_cicids2017_20260309_153012','two_stage','cicids2017',64,30,0.001,128,2,1,'completed',100,0.00244876,0.975142,'2026-03-09 15:30:12','2026-03-09 15:45:59',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(40,'CNN_2_cicids2017_20260309_154640','CNN_2','cicids2017',64,10,0.001,128,2,1,'completed',100,0.00748189,0.88662,'2026-03-09 15:46:40','2026-03-09 15:52:17',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(41,'two_stage_cicids2017_20260309_160717','two_stage','cicids2017',64,30,0.001,128,2,1,'completed',100,0.00183794,0.954397,'2026-03-09 16:07:17','2026-03-09 16:26:48',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(42,'CNN_2_cicids2017_20260309_203229','CNN_2','cicids2017',64,30,0.001,128,2,1,'completed',100,0.0222927,0.863616,'2026-03-09 20:32:29','2026-03-09 20:44:12',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(43,'two_stage_cicids2017_20260309_204842','two_stage','cicids2017',64,1,0.001,128,2,1,'completed',100,0.0225887,0.857081,'2026-03-09 20:48:42','2026-03-09 20:49:29',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(44,'two_stage_cicids2017_20260309_210126','two_stage','cicids2017',64,30,0.001,128,2,1,'running',8,0.116824,0.950108,'2026-03-09 21:01:26',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(45,'two_stage_cicids2017_20260309_210623','two_stage','cicids2017',64,30,0.001,128,2,1,'completed',100,0.00589106,0.951451,'2026-03-09 21:06:23','2026-03-09 21:22:28',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(46,'CNN_7_cicids2017_20260309_232252','CNN_7','cicids2017',64,30,0.001,128,2,1,'completed',100,0.0325425,0.850324,'2026-03-09 23:22:52','2026-03-09 23:29:52',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(47,'CNN_2_cicids2017_20260309_235311','CNN_2','cicids2017',64,30,0.001,128,2,1,'completed',100,0.0242088,0.854842,'2026-03-09 23:53:11','2026-03-10 00:04:19',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(48,'CNN_2_cicids2017_20260310_001007','CNN_2','cicids2017',64,30,0.001,128,2,1,'completed',100,0.0755675,0.971126,'2026-03-10 00:10:07','2026-03-10 00:22:36',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(49,'CNN_2_cicids2017_20260310_002601','CNN_2','cicids2017',64,30,0.001,128,2,1,'completed',100,0.0728773,0.967917,'2026-03-10 00:26:01','2026-03-10 00:39:11',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(50,'CNN_7_cicids2017_20260310_004249','CNN_7','cicids2017',64,20,0.001,128,2,1,'completed',100,0.0287933,0.85877,'2026-03-10 00:42:49','2026-03-10 00:50:19',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL),(51,'two_stage_cicids2017_20260310_005415','two_stage','cicids2017',64,30,0.001,128,2,1,'completed',100,0.00526638,0.953306,'2026-03-10 00:54:15','2026-03-10 01:12:22',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL);
/*!40000 ALTER TABLE `training_history` ENABLE KEYS */;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(50) COLLATE utf8mb4_unicode_ci NOT NULL,
  `password_hash` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `is_active` tinyint(1) DEFAULT NULL,
  `is_admin` tinyint(1) DEFAULT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_users_username` (`username`),
  KEY `ix_users_id` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users`
--

/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES (1,'admin','$2b$12$b8a04CkPGej53pi5harOFeVqYyFi7vxeshjxAAeCLj4/6YgpS7f56',1,1,'2026-03-05 22:13:32',NULL);
/*!40000 ALTER TABLE `users` ENABLE KEYS */;

--
-- Table structure for table `whitelist_ips`
--

DROP TABLE IF EXISTS `whitelist_ips`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `whitelist_ips` (
  `id` int NOT NULL AUTO_INCREMENT,
  `ip_address` varchar(50) COLLATE utf8mb4_unicode_ci NOT NULL,
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ip_address` (`ip_address`),
  KEY `ix_whitelist_ips_id` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `whitelist_ips`
--

/*!40000 ALTER TABLE `whitelist_ips` DISABLE KEYS */;
INSERT INTO `whitelist_ips` VALUES (5,'10.42.96.112','2026-03-06 14:01:30');
/*!40000 ALTER TABLE `whitelist_ips` ENABLE KEYS */;

--
-- Dumping routines for database 'ids'
--
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2026-03-17 14:31:59
