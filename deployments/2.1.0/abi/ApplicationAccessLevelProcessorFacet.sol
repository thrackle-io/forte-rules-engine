{"abi":[{"type":"function","name":"checkAccountDenyForNoAccessLevel","inputs":[{"name":"_accessLevel","type":"uint8","internalType":"uint8"}],"outputs":[],"stateMutability":"pure"},{"type":"function","name":"checkAccountMaxValueByAccessLevel","inputs":[{"name":"_ruleId","type":"uint32","internalType":"uint32"},{"name":"_accessLevel","type":"uint8","internalType":"uint8"},{"name":"_balance","type":"uint128","internalType":"uint128"},{"name":"_amountToTransfer","type":"uint128","internalType":"uint128"}],"outputs":[],"stateMutability":"view"},{"type":"function","name":"checkAccountMaxValueOutByAccessLevel","inputs":[{"name":"_ruleId","type":"uint32","internalType":"uint32"},{"name":"_accessLevel","type":"uint8","internalType":"uint8"},{"name":"_usdWithdrawalTotal","type":"uint128","internalType":"uint128"},{"name":"_usdAmountTransferring","type":"uint128","internalType":"uint128"}],"outputs":[{"name":"","type":"uint128","internalType":"uint128"}],"stateMutability":"view"},{"type":"function","name":"getAccountMaxValueByAccessLevel","inputs":[{"name":"_index","type":"uint32","internalType":"uint32"},{"name":"_accessLevel","type":"uint8","internalType":"uint8"}],"outputs":[{"name":"","type":"uint48","internalType":"uint48"}],"stateMutability":"view"},{"type":"function","name":"getAccountMaxValueOutByAccessLevel","inputs":[{"name":"_index","type":"uint32","internalType":"uint32"},{"name":"_accessLevel","type":"uint8","internalType":"uint8"}],"outputs":[{"name":"","type":"uint48","internalType":"uint48"}],"stateMutability":"view"},{"type":"function","name":"getTotalAccountMaxValueByAccessLevel","inputs":[],"outputs":[{"name":"","type":"uint32","internalType":"uint32"}],"stateMutability":"view"},{"type":"function","name":"getTotalAccountMaxValueOutByAccessLevel","inputs":[],"outputs":[{"name":"","type":"uint32","internalType":"uint32"}],"stateMutability":"view"},{"type":"error","name":"AccessLevelIsNotValid","inputs":[{"name":"accessLevel","type":"uint8","internalType":"uint8"}]},{"type":"error","name":"CantMixPeriodicAndNonPeriodic","inputs":[]},{"type":"error","name":"IndexOutOfRange","inputs":[]},{"type":"error","name":"InputArraysMustHaveSameLength","inputs":[]},{"type":"error","name":"InputArraysSizesNotValid","inputs":[]},{"type":"error","name":"InvalidOracleType","inputs":[{"name":"_type","type":"uint8","internalType":"uint8"}]},{"type":"error","name":"InvalidRuleInput","inputs":[]},{"type":"error","name":"InvertedLimits","inputs":[]},{"type":"error","name":"NotAllowedForAccessLevel","inputs":[]},{"type":"error","name":"NotEnoughBalance","inputs":[]},{"type":"error","name":"OverMaxValueByAccessLevel","inputs":[]},{"type":"error","name":"OverMaxValueOutByAccessLevel","inputs":[]},{"type":"error","name":"PeriodExceeds5Years","inputs":[]},{"type":"error","name":"RuleDoesNotExist","inputs":[]},{"type":"error","name":"ValueOutOfRange","inputs":[{"name":"_value","type":"uint256","internalType":"uint256"}]},{"type":"error","name":"WrongArrayOrder","inputs":[]},{"type":"error","name":"ZeroValueNotPermited","inputs":[]}],"bytecode":{"object":"0x608060405234801561001057600080fd5b506104b5806100206000396000f3fe608060405234801561001057600080fd5b506004361061007d5760003560e01c8063ac4db8071161005b578063ac4db807146100e3578063ad5dbad3146100eb578063bc8bace7146100fe578063f5c2ce591461012957600080fd5b80631713890a1461008257806332f0d3e3146100975780635a0e0ed4146100b9575b600080fd5b61009561009036600461036f565b61013c565b005b61009f61019d565b60405163ffffffff90911681526020015b60405180910390f35b6100cc6100c73660046103c3565b6101b8565b60405165ffffffffffff90911681526020016100b0565b61009f610226565b6100cc6100f93660046103c3565b610231565b61011161010c36600461036f565b61023c565b6040516001600160801b0390911681526020016100b0565b6100956101373660046103f6565b6102ab565b60006101488585610231565b905061016465ffffffffffff8216670de0b6b3a764000061042e565b61016e8484610445565b6001600160801b031611156101965760405163aee8b99360e01b815260040160405180910390fd5b5050505050565b6000806101a86102d2565b6001015463ffffffff1692915050565b6000806101c36102d2565b600181015490915063ffffffff908116908516106101f457604051631390f2a160e01b815260040160405180910390fd5b63ffffffff841660009081526020918252604080822060ff86168352909252205465ffffffffffff1690505b92915050565b6000806101a8610300565b6000806101c3610300565b60008061024986866101b8565b905061026565ffffffffffff8216670de0b6b3a764000061042e565b61026f8585610445565b6001600160801b03161115610297576040516308d857c560e41b815260040160405180910390fd5b6102a18385610445565b9695505050505050565b8060ff166000036102cf57604051633fac082d60e01b815260040160405180910390fd5b50565b60008061022060017fcd576fc088c5eb040f665f257428613253482a372b228b4e0451df92d88b2b2d61046c565b60008061022060017f4815e3fa667405e725c432fd6db2286588ecce84f997ea5bdb96e5e764a28d4861046c565b803563ffffffff8116811461034257600080fd5b919050565b803560ff8116811461034257600080fd5b80356001600160801b038116811461034257600080fd5b6000806000806080858703121561038557600080fd5b61038e8561032e565b935061039c60208601610347565b92506103aa60408601610358565b91506103b860608601610358565b905092959194509250565b600080604083850312156103d657600080fd5b6103df8361032e565b91506103ed60208401610347565b90509250929050565b60006020828403121561040857600080fd5b61041182610347565b9392505050565b634e487b7160e01b600052601160045260246000fd5b808202811582820484141761022057610220610418565b6001600160801b0381811683821601908082111561046557610465610418565b5092915050565b818103818111156102205761022061041856fea2646970667358221220514cb631fe4e7044bf6df7e1415303fcf06f0c8fd9e73d7e5c350065707bc48464736f6c63430008180033","sourceMap":"459:4681:238:-:0;;;;;;;;;;;;;;;;;;;","linkReferences":{}},"deployedBytecode":{"object":"0x608060405234801561001057600080fd5b506004361061007d5760003560e01c8063ac4db8071161005b578063ac4db807146100e3578063ad5dbad3146100eb578063bc8bace7146100fe578063f5c2ce591461012957600080fd5b80631713890a1461008257806332f0d3e3146100975780635a0e0ed4146100b9575b600080fd5b61009561009036600461036f565b61013c565b005b61009f61019d565b60405163ffffffff90911681526020015b60405180910390f35b6100cc6100c73660046103c3565b6101b8565b60405165ffffffffffff90911681526020016100b0565b61009f610226565b6100cc6100f93660046103c3565b610231565b61011161010c36600461036f565b61023c565b6040516001600160801b0390911681526020016100b0565b6100956101373660046103f6565b6102ab565b60006101488585610231565b905061016465ffffffffffff8216670de0b6b3a764000061042e565b61016e8484610445565b6001600160801b031611156101965760405163aee8b99360e01b815260040160405180910390fd5b5050505050565b6000806101a86102d2565b6001015463ffffffff1692915050565b6000806101c36102d2565b600181015490915063ffffffff908116908516106101f457604051631390f2a160e01b815260040160405180910390fd5b63ffffffff841660009081526020918252604080822060ff86168352909252205465ffffffffffff1690505b92915050565b6000806101a8610300565b6000806101c3610300565b60008061024986866101b8565b905061026565ffffffffffff8216670de0b6b3a764000061042e565b61026f8585610445565b6001600160801b03161115610297576040516308d857c560e41b815260040160405180910390fd5b6102a18385610445565b9695505050505050565b8060ff166000036102cf57604051633fac082d60e01b815260040160405180910390fd5b50565b60008061022060017fcd576fc088c5eb040f665f257428613253482a372b228b4e0451df92d88b2b2d61046c565b60008061022060017f4815e3fa667405e725c432fd6db2286588ecce84f997ea5bdb96e5e764a28d4861046c565b803563ffffffff8116811461034257600080fd5b919050565b803560ff8116811461034257600080fd5b80356001600160801b038116811461034257600080fd5b6000806000806080858703121561038557600080fd5b61038e8561032e565b935061039c60208601610347565b92506103aa60408601610358565b91506103b860608601610358565b905092959194509250565b600080604083850312156103d657600080fd5b6103df8361032e565b91506103ed60208401610347565b90509250929050565b60006020828403121561040857600080fd5b61041182610347565b9392505050565b634e487b7160e01b600052601160045260246000fd5b808202811582820484141761022057610220610418565b6001600160801b0381811683821601908082111561046557610465610418565b5092915050565b818103818111156102205761022061041856fea2646970667358221220514cb631fe4e7044bf6df7e1415303fcf06f0c8fd9e73d7e5c350065707bc48464736f6c63430008180033","sourceMap":"459:4681:238:-:0;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;1105:426;;;;;;:::i;:::-;;:::i;:::-;;4478:259;;;:::i;:::-;;;1118:10:398;1106:23;;;1088:42;;1076:2;1061:18;4478:259:238;;;;;;;;3919:398;;;;;;:::i;:::-;;:::i;:::-;;;1574:14:398;1562:27;;;1544:46;;1532:2;1517:18;3919:398:238;1400:196:398;2352:245:238;;;:::i;1836:383::-;;;;;;:::i;:::-;;:::i;3025:581::-;;;;;;:::i;:::-;;:::i;:::-;;;-1:-1:-1;;;;;1765:47:398;;;1747:66;;1735:2;1720:18;3025:581:238;1601:218:398;4965:173:238;;;;;;:::i;:::-;;:::i;1105:426::-;1253:10;1266:54;1298:7;1307:12;1266:31;:54::i;:::-;1253:67;-1:-1:-1;1462:25:238;:12;;;1478:8;1462:25;:::i;:::-;1430:28;1450:8;1430:17;:28;:::i;:::-;-1:-1:-1;;;;;1430:58:238;;1426:98;;;1497:27;;-1:-1:-1;;;1497:27:238;;;;;;;;;;;1426:98;1243:288;1105:426;;;;:::o;4478:259::-;4552:6;4570:51;4624:48;:46;:48::i;:::-;4689:41;;;;;;4478:259;-1:-1:-1;;4478:259:238:o;3919:398::-;4019:6;4037:51;4091:48;:46;:48::i;:::-;4163:41;;;;4037:102;;-1:-1:-1;4163:41:238;;;;4153:51;;;;4149:81;;4213:17;;-1:-1:-1;;;4213:17:238;;;;;;;;;;;4149:81;4247:49;;;:41;:49;;;;;;;;;;;:63;;;;;;;;;;;;;-1:-1:-1;3919:398:238;;;;;:::o;2352:245::-;2421:6;2439:48;2490:45;:43;:45::i;1836:383::-;1933:6;1951:48;2002:45;:43;:45::i;3025:581::-;3191:7;3210:10;3223:57;3258:7;3267:12;3223:34;:57::i;:::-;3210:70;-1:-1:-1;3438:25:238;:12;;;3454:8;3438:25;:::i;:::-;3390:44;3415:19;3390:22;:44;:::i;:::-;-1:-1:-1;;;;;3390:74:238;;3386:177;;;3473:30;;-1:-1:-1;;;3473:30:238;;;;;;;;;;;3386:177;3518:45;3541:22;3518:45;;:::i;:::-;;3025:581;-1:-1:-1;;;;;;3025:581:238:o;4965:173::-;5055:12;:17;;5071:1;5055:17;5051:81;;5095:26;;-1:-1:-1;;;5095:26:238;;;;;;;;;;;5051:81;4965:173;:::o;8476:267:254:-;8549:56;;2431:63;2493:1;2439:50;2431:63;:::i;6147:260::-;6217:53;;1813:59;1871:1;1821:46;1813:59;:::i;14:163:398:-;81:20;;141:10;130:22;;120:33;;110:61;;167:1;164;157:12;110:61;14:163;;;:::o;182:156::-;248:20;;308:4;297:16;;287:27;;277:55;;328:1;325;318:12;343:188;411:20;;-1:-1:-1;;;;;460:46:398;;450:57;;440:85;;521:1;518;511:12;536:403;619:6;627;635;643;696:3;684:9;675:7;671:23;667:33;664:53;;;713:1;710;703:12;664:53;736:28;754:9;736:28;:::i;:::-;726:38;;783:36;815:2;804:9;800:18;783:36;:::i;:::-;773:46;;838:38;872:2;861:9;857:18;838:38;:::i;:::-;828:48;;895:38;929:2;918:9;914:18;895:38;:::i;:::-;885:48;;536:403;;;;;;;:::o;1141:254::-;1206:6;1214;1267:2;1255:9;1246:7;1242:23;1238:32;1235:52;;;1283:1;1280;1273:12;1235:52;1306:28;1324:9;1306:28;:::i;:::-;1296:38;;1353:36;1385:2;1374:9;1370:18;1353:36;:::i;:::-;1343:46;;1141:254;;;;;:::o;1824:182::-;1881:6;1934:2;1922:9;1913:7;1909:23;1905:32;1902:52;;;1950:1;1947;1940:12;1902:52;1973:27;1990:9;1973:27;:::i;:::-;1963:37;1824:182;-1:-1:-1;;;1824:182:398:o;2011:127::-;2072:10;2067:3;2063:20;2060:1;2053:31;2103:4;2100:1;2093:15;2127:4;2124:1;2117:15;2143:168;2216:9;;;2247;;2264:15;;;2258:22;;2244:37;2234:71;;2285:18;;:::i;2316:197::-;-1:-1:-1;;;;;2438:10:398;;;2450;;;2434:27;;2473:11;;;2470:37;;;2487:18;;:::i;:::-;2470:37;2316:197;;;;:::o;2518:128::-;2585:9;;;2606:11;;;2603:37;;;2620:18;;:::i","linkReferences":{}},"methodIdentifiers":{"checkAccountDenyForNoAccessLevel(uint8)":"f5c2ce59","checkAccountMaxValueByAccessLevel(uint32,uint8,uint128,uint128)":"1713890a","checkAccountMaxValueOutByAccessLevel(uint32,uint8,uint128,uint128)":"bc8bace7","getAccountMaxValueByAccessLevel(uint32,uint8)":"ad5dbad3","getAccountMaxValueOutByAccessLevel(uint32,uint8)":"5a0e0ed4","getTotalAccountMaxValueByAccessLevel()":"ac4db807","getTotalAccountMaxValueOutByAccessLevel()":"32f0d3e3"},"rawMetadata":"{\"compiler\":{\"version\":\"0.8.24+commit.e11b9ed9\"},\"language\":\"Solidity\",\"output\":{\"abi\":[{\"inputs\":[{\"internalType\":\"uint8\",\"name\":\"accessLevel\",\"type\":\"uint8\"}],\"name\":\"AccessLevelIsNotValid\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"CantMixPeriodicAndNonPeriodic\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"IndexOutOfRange\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"InputArraysMustHaveSameLength\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"InputArraysSizesNotValid\",\"type\":\"error\"},{\"inputs\":[{\"internalType\":\"uint8\",\"name\":\"_type\",\"type\":\"uint8\"}],\"name\":\"InvalidOracleType\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"InvalidRuleInput\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"InvertedLimits\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"NotAllowedForAccessLevel\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"NotEnoughBalance\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"OverMaxValueByAccessLevel\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"OverMaxValueOutByAccessLevel\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"PeriodExceeds5Years\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"RuleDoesNotExist\",\"type\":\"error\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"_value\",\"type\":\"uint256\"}],\"name\":\"ValueOutOfRange\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"WrongArrayOrder\",\"type\":\"error\"},{\"inputs\":[],\"name\":\"ZeroValueNotPermited\",\"type\":\"error\"},{\"inputs\":[{\"internalType\":\"uint8\",\"name\":\"_accessLevel\",\"type\":\"uint8\"}],\"name\":\"checkAccountDenyForNoAccessLevel\",\"outputs\":[],\"stateMutability\":\"pure\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_ruleId\",\"type\":\"uint32\"},{\"internalType\":\"uint8\",\"name\":\"_accessLevel\",\"type\":\"uint8\"},{\"internalType\":\"uint128\",\"name\":\"_balance\",\"type\":\"uint128\"},{\"internalType\":\"uint128\",\"name\":\"_amountToTransfer\",\"type\":\"uint128\"}],\"name\":\"checkAccountMaxValueByAccessLevel\",\"outputs\":[],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_ruleId\",\"type\":\"uint32\"},{\"internalType\":\"uint8\",\"name\":\"_accessLevel\",\"type\":\"uint8\"},{\"internalType\":\"uint128\",\"name\":\"_usdWithdrawalTotal\",\"type\":\"uint128\"},{\"internalType\":\"uint128\",\"name\":\"_usdAmountTransferring\",\"type\":\"uint128\"}],\"name\":\"checkAccountMaxValueOutByAccessLevel\",\"outputs\":[{\"internalType\":\"uint128\",\"name\":\"\",\"type\":\"uint128\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_index\",\"type\":\"uint32\"},{\"internalType\":\"uint8\",\"name\":\"_accessLevel\",\"type\":\"uint8\"}],\"name\":\"getAccountMaxValueByAccessLevel\",\"outputs\":[{\"internalType\":\"uint48\",\"name\":\"\",\"type\":\"uint48\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint32\",\"name\":\"_index\",\"type\":\"uint32\"},{\"internalType\":\"uint8\",\"name\":\"_accessLevel\",\"type\":\"uint8\"}],\"name\":\"getAccountMaxValueOutByAccessLevel\",\"outputs\":[{\"internalType\":\"uint48\",\"name\":\"\",\"type\":\"uint48\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getTotalAccountMaxValueByAccessLevel\",\"outputs\":[{\"internalType\":\"uint32\",\"name\":\"\",\"type\":\"uint32\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getTotalAccountMaxValueOutByAccessLevel\",\"outputs\":[{\"internalType\":\"uint32\",\"name\":\"\",\"type\":\"uint32\"}],\"stateMutability\":\"view\",\"type\":\"function\"}],\"devdoc\":{\"author\":\"@ShaneDuncan602 @oscarsernarosero @TJ-Everett\",\"details\":\"This contract implements rules to be checked by am Application Handler.\",\"kind\":\"dev\",\"methods\":{\"checkAccountDenyForNoAccessLevel(uint8)\":{\"details\":\"Check if transaction passes Account Deny For No Access Level rule.This has no stored rule as there are no additional variables needed.\",\"params\":{\"_accessLevel\":\"the Access Level of the account\"}},\"checkAccountMaxValueByAccessLevel(uint32,uint8,uint128,uint128)\":{\"details\":\"Check if transaction passes Account Max Value By AccessLevel rule.\",\"params\":{\"_accessLevel\":\"the Access Level of the account\",\"_amountToTransfer\":\"total USD amount to be transferred with 18 decimals of precision\",\"_balance\":\"account's beginning balance in USD with 18 decimals of precision\",\"_ruleId\":\"Rule Identifier for rule arguments\"}},\"checkAccountMaxValueOutByAccessLevel(uint32,uint8,uint128,uint128)\":{\"details\":\"Check if transaction passes Account Max Value Out By Access Level rule.\",\"params\":{\"_accessLevel\":\"the Access Level of the account\",\"_ruleId\":\"Rule Identifier for rule arguments\",\"_usdAmountTransferring\":\"total USD amount to be transferred with 18 decimals of precision\",\"_usdWithdrawalTotal\":\"account's total amount withdrawn in USD with 18 decimals of precision\"}},\"getAccountMaxValueByAccessLevel(uint32,uint8)\":{\"details\":\"Function to get the Account Max Value By Access Level rule in the rule set that belongs to the Access Level\",\"params\":{\"_accessLevel\":\"AccessLevel Level to check\",\"_index\":\"position of rule in array\"},\"returns\":{\"_0\":\"balanceAmount balance allowed for access level\"}},\"getAccountMaxValueOutByAccessLevel(uint32,uint8)\":{\"details\":\"Function to get the Account Max Value Out By Access Level rule in the rule set that belongs to the Access Level\",\"params\":{\"_accessLevel\":\"AccessLevel Level to check\",\"_index\":\"position of rule in array\"},\"returns\":{\"_0\":\"balanceAmount balance allowed for access level\"}},\"getTotalAccountMaxValueByAccessLevel()\":{\"details\":\"Function to get total Account Max Value By Access Level rules\",\"returns\":{\"_0\":\"Total length of array\"}},\"getTotalAccountMaxValueOutByAccessLevel()\":{\"details\":\"Function to get total Account Max Value Out By Access Level rules\",\"returns\":{\"_0\":\"Total number of access level withdrawal rules\"}}},\"title\":\"Access Level Processor Facet\",\"version\":1},\"userdoc\":{\"kind\":\"user\",\"methods\":{},\"notice\":\"Implements Access Level Rule Checks. Access Level rules are measured in in terms of USD with 18 decimals of precision.\",\"version\":1}},\"settings\":{\"compilationTarget\":{\"src/protocol/economic/ruleProcessor/ApplicationAccessLevelProcessorFacet.sol\":\"ApplicationAccessLevelProcessorFacet\"},\"evmVersion\":\"paris\",\"libraries\":{},\"metadata\":{\"bytecodeHash\":\"ipfs\"},\"optimizer\":{\"enabled\":true,\"runs\":200},\"remappings\":[\":@openzeppelin/contracts-upgradeable/=lib/openzeppelin-contracts-upgradeable/contracts/\",\":@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/\",\":diamond-std/=lib/diamond-std/\",\":ds-test/=lib/forge-std/lib/ds-test/src/\",\":erc4626-tests/=lib/openzeppelin-contracts-upgradeable/lib/erc4626-tests/\",\":forge-std/=lib/forge-std/src/\",\":openzeppelin-contracts-upgradeable/=lib/openzeppelin-contracts-upgradeable/\",\":openzeppelin-contracts/=lib/openzeppelin-contracts/\",\":openzeppelin/=lib/openzeppelin-contracts-upgradeable/contracts/\"]},\"sources\":{\"lib/diamond-std/core/DiamondCut/FacetCut.sol\":{\"keccak256\":\"0x20816015bfdcd3885faafc4c1b90f96c614c3f21e02e1c6022069568aaf425d3\",\"license\":\"MIT\",\"urls\":[\"bzz-raw://5d8f60b2f3f806e21b1f654af3179b9b9d1a1f9ca6b31da158e7daac7f61af8d\",\"dweb:/ipfs/QmWJDgFwrYKD6Fyer2tg9Q1vMhnS7acphoYd6daTch7Wae\"]},\"lib/diamond-std/implementations/ERC173/ERC173.sol\":{\"keccak256\":\"0xdaad09beced3c7ec1990e785b3640d714448dd69b3c94dc7d372e5a9c9134a43\",\"license\":\"UNLICENSED\",\"urls\":[\"bzz-raw://b39617464e2bb7c2b54ac33b66acf6f71c3b4816bfd25ab8df5410c09b389744\",\"dweb:/ipfs/QmSHj6qZEGxD6fKnapapwX1GRc5M8hFwhyqXKvnqFe2FWJ\"]},\"lib/diamond-std/implementations/ERC173/ERC173Lib.sol\":{\"keccak256\":\"0x5b84a93ec7b070e4c5f4c82c4c8598a656a2c44296065bfa9370aa61899f09e7\",\"license\":\"UNLICENSED\",\"urls\":[\"bzz-raw://53513b6263b714e6e705e8b02ae0dd84a0bd8dc78048d86e2384d68cad09e2cc\",\"dweb:/ipfs/QmRTkkds4KxhekV2CLzNJ2sGdYRCxwuGqzJA7uUsdBM8AG\"]},\"src/common/ActionEnum.sol\":{\"keccak256\":\"0xe40c1173f45de46d72872d52d81fa915fd328d5b717a9264324518268b95ee6d\",\"license\":\"BUSL-1.1\",\"urls\":[\"bzz-raw://a53d3b84ccb944a6e0b8b756b0e5bc16f4ef45131c098c0eaabe8c9d2e58c863\",\"dweb:/ipfs/QmfTUpUYnM4er8EUhnoXe8wH2jZhqr11KSqatDjnoXYhog\"]},\"src/common/IErrors.sol\":{\"keccak256\":\"0x2c4160cc78cf3c5143380ef73b6f1a25465f202c4e1abd4b9a37d62011ffb72f\",\"license\":\"BUSL-1.1\",\"urls\":[\"bzz-raw://dd901f31c572bdf1a5a76b921c8b0818feec19bda554f7a54ad34b89cadbd8eb\",\"dweb:/ipfs/QmSKYkCaTgCDpRouQ8ZF2VbZbvBaWPP6HPQybJtPSTi6ay\"]},\"src/common/IEvents.sol\":{\"keccak256\":\"0xe953b9baadfc2dcd3ef239f79dec5d88ce4c603c7439da9069c4c2d6dd14771e\",\"license\":\"BUSL-1.1\",\"urls\":[\"bzz-raw://d496dfd37c8acc97872530ed114cd55634a7fb9033354174c203574d05f6ccaa\",\"dweb:/ipfs/QmdKZ3bgNHz7MinYm54neyXp3oh7ZckSrYF1XPTU9t7xFr\"]},\"src/protocol/economic/ruleProcessor/ApplicationAccessLevelProcessorFacet.sol\":{\"keccak256\":\"0x1187fe45f6a6be24325622a3440a8836eddfd1ac1654d8b693f487219b6a4153\",\"license\":\"BUSL-1.1\",\"urls\":[\"bzz-raw://3bfbd7b41ec46e8c654315b494364c22ba400e8019b5c96084606b9f029b7132\",\"dweb:/ipfs/QmNfymbHPaj8jpRaKCTgLQvZjAtijgif6H3FD9TfyHfhyF\"]},\"src/protocol/economic/ruleProcessor/IRuleStorage.sol\":{\"keccak256\":\"0x69bc06d71883005b209c8957d62fa6ee17b38a000afd0175df4d167c5b7890c4\",\"license\":\"BUSL-1.1\",\"urls\":[\"bzz-raw://4edabeb1f193770dd1d7f6b4c83a0c53712ac9b256d16d24f881b8b5b25cdabe\",\"dweb:/ipfs/QmVhxhHNtSPyc5J9vZQHGjR6Va2vpks4hhZtL8BtdCEXdW\"]},\"src/protocol/economic/ruleProcessor/RuleCodeData.sol\":{\"keccak256\":\"0x2512ce1feea98053fa5fbca8827f197060f3c0bc22e26b3ec7aba5650b2d708f\",\"license\":\"BUSL-1.1\",\"urls\":[\"bzz-raw://ca9cfcee12da58270e8fcb57b94a981c1fecffdb381c94dfefe2d2c1497da744\",\"dweb:/ipfs/QmSJZ6iQZoeMSaKrZVctEJZy4CgLVnTFN8W9Ho3Hb929zf\"]},\"src/protocol/economic/ruleProcessor/RuleDataInterfaces.sol\":{\"keccak256\":\"0xf49dc5c3678e1ffc2c94b14533df6151ac8ec6323a300439948cb0784a072ed5\",\"license\":\"BUSL-1.1\",\"urls\":[\"bzz-raw://a0b557a52fce4aa4d3510ff5507d46ceb590a9e5bb07ac55e6130baab803def0\",\"dweb:/ipfs/QmS3fLCHuQ2ANB2hZV5PDNHKM6KJvw6oj69jnzGsruE2PG\"]},\"src/protocol/economic/ruleProcessor/RuleProcessorCommonLib.sol\":{\"keccak256\":\"0xc1c183da762734fbfa5c3ab4dfc71270565505df63d1c6cd8578aa25e92b63cb\",\"license\":\"BUSL-1.1\",\"urls\":[\"bzz-raw://0a89b8b63d77d40b704e8d8e9920393208d7326b6d3d27946fd2f0d58dea6a6b\",\"dweb:/ipfs/QmYKXozBGLgGcKt8D9nuhJxoSnQKCUqJVu8oBqNucfSzZE\"]},\"src/protocol/economic/ruleProcessor/RuleProcessorDiamondImports.sol\":{\"keccak256\":\"0x5f3d8eb51ab70a3610bcaf0b107751087c857ab15f405febf14d864bfd076743\",\"license\":\"BUSL-1.1\",\"urls\":[\"bzz-raw://c9d4c98c01b268a78382fc676bc76f94ce41fb0602acd7b01354a5bdd47b2864\",\"dweb:/ipfs/QmZcagiZyo4rmW4C8Skyw54No9a6cgNKr2EJVpCe9L2kGJ\"]},\"src/protocol/economic/ruleProcessor/RuleProcessorDiamondLib.sol\":{\"keccak256\":\"0x4f3304bb346213363e449b7a6a5640a81509f5b10ff8abbb36b1796c1e5439e1\",\"license\":\"BUSL-1.1\",\"urls\":[\"bzz-raw://583b9bf9cbcbd134875a1d7ce8809849a1ce03cd79e42f06a2a44eb8416e62ba\",\"dweb:/ipfs/QmVu2qRJ5DNeGUjgbh7otHTZGgLJkqMa19fhhXC79Y1yPU\"]},\"src/protocol/economic/ruleProcessor/RuleStoragePositionLib.sol\":{\"keccak256\":\"0x55306ea393b072103fc86cc0e8eb1f7530ab557b7d495a8e6ca6cc9d75abdddd\",\"license\":\"BUSL-1.1\",\"urls\":[\"bzz-raw://f669304f83b65b124690f7a5221d3d9c14aa8a6f2eecebeb79a3998618eddb77\",\"dweb:/ipfs/QmQwtMGpXngzJ2HE2jfqa8PwwQNghiWio42kuLewTYjJDa\"]}},\"version\":1}","metadata":{"compiler":{"version":"0.8.24+commit.e11b9ed9"},"language":"Solidity","output":{"abi":[{"inputs":[{"internalType":"uint8","name":"accessLevel","type":"uint8"}],"type":"error","name":"AccessLevelIsNotValid"},{"inputs":[],"type":"error","name":"CantMixPeriodicAndNonPeriodic"},{"inputs":[],"type":"error","name":"IndexOutOfRange"},{"inputs":[],"type":"error","name":"InputArraysMustHaveSameLength"},{"inputs":[],"type":"error","name":"InputArraysSizesNotValid"},{"inputs":[{"internalType":"uint8","name":"_type","type":"uint8"}],"type":"error","name":"InvalidOracleType"},{"inputs":[],"type":"error","name":"InvalidRuleInput"},{"inputs":[],"type":"error","name":"InvertedLimits"},{"inputs":[],"type":"error","name":"NotAllowedForAccessLevel"},{"inputs":[],"type":"error","name":"NotEnoughBalance"},{"inputs":[],"type":"error","name":"OverMaxValueByAccessLevel"},{"inputs":[],"type":"error","name":"OverMaxValueOutByAccessLevel"},{"inputs":[],"type":"error","name":"PeriodExceeds5Years"},{"inputs":[],"type":"error","name":"RuleDoesNotExist"},{"inputs":[{"internalType":"uint256","name":"_value","type":"uint256"}],"type":"error","name":"ValueOutOfRange"},{"inputs":[],"type":"error","name":"WrongArrayOrder"},{"inputs":[],"type":"error","name":"ZeroValueNotPermited"},{"inputs":[{"internalType":"uint8","name":"_accessLevel","type":"uint8"}],"stateMutability":"pure","type":"function","name":"checkAccountDenyForNoAccessLevel"},{"inputs":[{"internalType":"uint32","name":"_ruleId","type":"uint32"},{"internalType":"uint8","name":"_accessLevel","type":"uint8"},{"internalType":"uint128","name":"_balance","type":"uint128"},{"internalType":"uint128","name":"_amountToTransfer","type":"uint128"}],"stateMutability":"view","type":"function","name":"checkAccountMaxValueByAccessLevel"},{"inputs":[{"internalType":"uint32","name":"_ruleId","type":"uint32"},{"internalType":"uint8","name":"_accessLevel","type":"uint8"},{"internalType":"uint128","name":"_usdWithdrawalTotal","type":"uint128"},{"internalType":"uint128","name":"_usdAmountTransferring","type":"uint128"}],"stateMutability":"view","type":"function","name":"checkAccountMaxValueOutByAccessLevel","outputs":[{"internalType":"uint128","name":"","type":"uint128"}]},{"inputs":[{"internalType":"uint32","name":"_index","type":"uint32"},{"internalType":"uint8","name":"_accessLevel","type":"uint8"}],"stateMutability":"view","type":"function","name":"getAccountMaxValueByAccessLevel","outputs":[{"internalType":"uint48","name":"","type":"uint48"}]},{"inputs":[{"internalType":"uint32","name":"_index","type":"uint32"},{"internalType":"uint8","name":"_accessLevel","type":"uint8"}],"stateMutability":"view","type":"function","name":"getAccountMaxValueOutByAccessLevel","outputs":[{"internalType":"uint48","name":"","type":"uint48"}]},{"inputs":[],"stateMutability":"view","type":"function","name":"getTotalAccountMaxValueByAccessLevel","outputs":[{"internalType":"uint32","name":"","type":"uint32"}]},{"inputs":[],"stateMutability":"view","type":"function","name":"getTotalAccountMaxValueOutByAccessLevel","outputs":[{"internalType":"uint32","name":"","type":"uint32"}]}],"devdoc":{"kind":"dev","methods":{"checkAccountDenyForNoAccessLevel(uint8)":{"details":"Check if transaction passes Account Deny For No Access Level rule.This has no stored rule as there are no additional variables needed.","params":{"_accessLevel":"the Access Level of the account"}},"checkAccountMaxValueByAccessLevel(uint32,uint8,uint128,uint128)":{"details":"Check if transaction passes Account Max Value By AccessLevel rule.","params":{"_accessLevel":"the Access Level of the account","_amountToTransfer":"total USD amount to be transferred with 18 decimals of precision","_balance":"account's beginning balance in USD with 18 decimals of precision","_ruleId":"Rule Identifier for rule arguments"}},"checkAccountMaxValueOutByAccessLevel(uint32,uint8,uint128,uint128)":{"details":"Check if transaction passes Account Max Value Out By Access Level rule.","params":{"_accessLevel":"the Access Level of the account","_ruleId":"Rule Identifier for rule arguments","_usdAmountTransferring":"total USD amount to be transferred with 18 decimals of precision","_usdWithdrawalTotal":"account's total amount withdrawn in USD with 18 decimals of precision"}},"getAccountMaxValueByAccessLevel(uint32,uint8)":{"details":"Function to get the Account Max Value By Access Level rule in the rule set that belongs to the Access Level","params":{"_accessLevel":"AccessLevel Level to check","_index":"position of rule in array"},"returns":{"_0":"balanceAmount balance allowed for access level"}},"getAccountMaxValueOutByAccessLevel(uint32,uint8)":{"details":"Function to get the Account Max Value Out By Access Level rule in the rule set that belongs to the Access Level","params":{"_accessLevel":"AccessLevel Level to check","_index":"position of rule in array"},"returns":{"_0":"balanceAmount balance allowed for access level"}},"getTotalAccountMaxValueByAccessLevel()":{"details":"Function to get total Account Max Value By Access Level rules","returns":{"_0":"Total length of array"}},"getTotalAccountMaxValueOutByAccessLevel()":{"details":"Function to get total Account Max Value Out By Access Level rules","returns":{"_0":"Total number of access level withdrawal rules"}}},"version":1},"userdoc":{"kind":"user","methods":{},"version":1}},"settings":{"remappings":["@openzeppelin/contracts-upgradeable/=lib/openzeppelin-contracts-upgradeable/contracts/","@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/","diamond-std/=lib/diamond-std/","ds-test/=lib/forge-std/lib/ds-test/src/","erc4626-tests/=lib/openzeppelin-contracts-upgradeable/lib/erc4626-tests/","forge-std/=lib/forge-std/src/","openzeppelin-contracts-upgradeable/=lib/openzeppelin-contracts-upgradeable/","openzeppelin-contracts/=lib/openzeppelin-contracts/","openzeppelin/=lib/openzeppelin-contracts-upgradeable/contracts/"],"optimizer":{"enabled":true,"runs":200},"metadata":{"bytecodeHash":"ipfs"},"compilationTarget":{"src/protocol/economic/ruleProcessor/ApplicationAccessLevelProcessorFacet.sol":"ApplicationAccessLevelProcessorFacet"},"evmVersion":"paris","libraries":{}},"sources":{"lib/diamond-std/core/DiamondCut/FacetCut.sol":{"keccak256":"0x20816015bfdcd3885faafc4c1b90f96c614c3f21e02e1c6022069568aaf425d3","urls":["bzz-raw://5d8f60b2f3f806e21b1f654af3179b9b9d1a1f9ca6b31da158e7daac7f61af8d","dweb:/ipfs/QmWJDgFwrYKD6Fyer2tg9Q1vMhnS7acphoYd6daTch7Wae"],"license":"MIT"},"lib/diamond-std/implementations/ERC173/ERC173.sol":{"keccak256":"0xdaad09beced3c7ec1990e785b3640d714448dd69b3c94dc7d372e5a9c9134a43","urls":["bzz-raw://b39617464e2bb7c2b54ac33b66acf6f71c3b4816bfd25ab8df5410c09b389744","dweb:/ipfs/QmSHj6qZEGxD6fKnapapwX1GRc5M8hFwhyqXKvnqFe2FWJ"],"license":"UNLICENSED"},"lib/diamond-std/implementations/ERC173/ERC173Lib.sol":{"keccak256":"0x5b84a93ec7b070e4c5f4c82c4c8598a656a2c44296065bfa9370aa61899f09e7","urls":["bzz-raw://53513b6263b714e6e705e8b02ae0dd84a0bd8dc78048d86e2384d68cad09e2cc","dweb:/ipfs/QmRTkkds4KxhekV2CLzNJ2sGdYRCxwuGqzJA7uUsdBM8AG"],"license":"UNLICENSED"},"src/common/ActionEnum.sol":{"keccak256":"0xe40c1173f45de46d72872d52d81fa915fd328d5b717a9264324518268b95ee6d","urls":["bzz-raw://a53d3b84ccb944a6e0b8b756b0e5bc16f4ef45131c098c0eaabe8c9d2e58c863","dweb:/ipfs/QmfTUpUYnM4er8EUhnoXe8wH2jZhqr11KSqatDjnoXYhog"],"license":"BUSL-1.1"},"src/common/IErrors.sol":{"keccak256":"0x2c4160cc78cf3c5143380ef73b6f1a25465f202c4e1abd4b9a37d62011ffb72f","urls":["bzz-raw://dd901f31c572bdf1a5a76b921c8b0818feec19bda554f7a54ad34b89cadbd8eb","dweb:/ipfs/QmSKYkCaTgCDpRouQ8ZF2VbZbvBaWPP6HPQybJtPSTi6ay"],"license":"BUSL-1.1"},"src/common/IEvents.sol":{"keccak256":"0xe953b9baadfc2dcd3ef239f79dec5d88ce4c603c7439da9069c4c2d6dd14771e","urls":["bzz-raw://d496dfd37c8acc97872530ed114cd55634a7fb9033354174c203574d05f6ccaa","dweb:/ipfs/QmdKZ3bgNHz7MinYm54neyXp3oh7ZckSrYF1XPTU9t7xFr"],"license":"BUSL-1.1"},"src/protocol/economic/ruleProcessor/ApplicationAccessLevelProcessorFacet.sol":{"keccak256":"0x1187fe45f6a6be24325622a3440a8836eddfd1ac1654d8b693f487219b6a4153","urls":["bzz-raw://3bfbd7b41ec46e8c654315b494364c22ba400e8019b5c96084606b9f029b7132","dweb:/ipfs/QmNfymbHPaj8jpRaKCTgLQvZjAtijgif6H3FD9TfyHfhyF"],"license":"BUSL-1.1"},"src/protocol/economic/ruleProcessor/IRuleStorage.sol":{"keccak256":"0x69bc06d71883005b209c8957d62fa6ee17b38a000afd0175df4d167c5b7890c4","urls":["bzz-raw://4edabeb1f193770dd1d7f6b4c83a0c53712ac9b256d16d24f881b8b5b25cdabe","dweb:/ipfs/QmVhxhHNtSPyc5J9vZQHGjR6Va2vpks4hhZtL8BtdCEXdW"],"license":"BUSL-1.1"},"src/protocol/economic/ruleProcessor/RuleCodeData.sol":{"keccak256":"0x2512ce1feea98053fa5fbca8827f197060f3c0bc22e26b3ec7aba5650b2d708f","urls":["bzz-raw://ca9cfcee12da58270e8fcb57b94a981c1fecffdb381c94dfefe2d2c1497da744","dweb:/ipfs/QmSJZ6iQZoeMSaKrZVctEJZy4CgLVnTFN8W9Ho3Hb929zf"],"license":"BUSL-1.1"},"src/protocol/economic/ruleProcessor/RuleDataInterfaces.sol":{"keccak256":"0xf49dc5c3678e1ffc2c94b14533df6151ac8ec6323a300439948cb0784a072ed5","urls":["bzz-raw://a0b557a52fce4aa4d3510ff5507d46ceb590a9e5bb07ac55e6130baab803def0","dweb:/ipfs/QmS3fLCHuQ2ANB2hZV5PDNHKM6KJvw6oj69jnzGsruE2PG"],"license":"BUSL-1.1"},"src/protocol/economic/ruleProcessor/RuleProcessorCommonLib.sol":{"keccak256":"0xc1c183da762734fbfa5c3ab4dfc71270565505df63d1c6cd8578aa25e92b63cb","urls":["bzz-raw://0a89b8b63d77d40b704e8d8e9920393208d7326b6d3d27946fd2f0d58dea6a6b","dweb:/ipfs/QmYKXozBGLgGcKt8D9nuhJxoSnQKCUqJVu8oBqNucfSzZE"],"license":"BUSL-1.1"},"src/protocol/economic/ruleProcessor/RuleProcessorDiamondImports.sol":{"keccak256":"0x5f3d8eb51ab70a3610bcaf0b107751087c857ab15f405febf14d864bfd076743","urls":["bzz-raw://c9d4c98c01b268a78382fc676bc76f94ce41fb0602acd7b01354a5bdd47b2864","dweb:/ipfs/QmZcagiZyo4rmW4C8Skyw54No9a6cgNKr2EJVpCe9L2kGJ"],"license":"BUSL-1.1"},"src/protocol/economic/ruleProcessor/RuleProcessorDiamondLib.sol":{"keccak256":"0x4f3304bb346213363e449b7a6a5640a81509f5b10ff8abbb36b1796c1e5439e1","urls":["bzz-raw://583b9bf9cbcbd134875a1d7ce8809849a1ce03cd79e42f06a2a44eb8416e62ba","dweb:/ipfs/QmVu2qRJ5DNeGUjgbh7otHTZGgLJkqMa19fhhXC79Y1yPU"],"license":"BUSL-1.1"},"src/protocol/economic/ruleProcessor/RuleStoragePositionLib.sol":{"keccak256":"0x55306ea393b072103fc86cc0e8eb1f7530ab557b7d495a8e6ca6cc9d75abdddd","urls":["bzz-raw://f669304f83b65b124690f7a5221d3d9c14aa8a6f2eecebeb79a3998618eddb77","dweb:/ipfs/QmQwtMGpXngzJ2HE2jfqa8PwwQNghiWio42kuLewTYjJDa"],"license":"BUSL-1.1"}},"version":1},"id":238}