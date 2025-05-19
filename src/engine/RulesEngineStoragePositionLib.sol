// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;
import "src/engine/RulesEngineStorageStructure.sol";

/**
 * @title Rules Engine Storage Position Library
 * @dev This library provides functions to access and manage storage positions for various components of the Rules Engine.
 *      It defines fixed storage slots for initialized flags, foreign calls, trackers, function signatures, rules, policies, 
 *      and policy associations. These storage slots are used to ensure consistent and conflict-free storage management 
 *      across the diamond proxy pattern.
 * @notice This library is a critical component of the Rules Engine, enabling modular and efficient storage management.
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220
 */
library RulesEngineStoragePositionLib {
    bytes32 constant DIAMOND_CUT_STORAGE_ENGINE_POS = bytes32(uint256(keccak256("diamond-cut.storage-engine")) - 1);
    bytes32 constant INITIALIZED_POSITION = bytes32(uint256(keccak256("initialized-position")) - 1);
    bytes32 constant FOREIGN_CALL_POSITION = bytes32(uint256(keccak256("foreign-call-position")) - 1);
    bytes32 constant TRACKER_POSITION = bytes32(uint256(keccak256("tracker-position")) - 1);
    bytes32 constant FUNCTION_SIGNATURE_POSITION = bytes32(uint256(keccak256("function-signature-position")) - 1);
    bytes32 constant RULE_POSITION = bytes32(uint256(keccak256("rule-position")) - 1);
    bytes32 constant POLICY_POSITION = bytes32(uint256(keccak256("policy-position")) - 1);
    bytes32 constant POLICY_ASSOCIATION_POSITION = bytes32(uint256(keccak256("policy-association-position")) - 1);
    bytes32 constant FOREIGN_CALL_METADATA_POSITION = bytes32(uint256(keccak256("foreign-call-metadata-position")) - 1);
    bytes32 constant FUNCTION_SIGNATURE_METADATA_POSITION = bytes32(uint256(keccak256("function-signature-metadata-position")) - 1);
    bytes32 constant TRACKER_METADATA_POSITION = bytes32(uint256(keccak256("tracker-metadata-position")) - 1);

    /**
     * @notice Retrieves the storage for the initialized flag.
     * @dev Uses a fixed storage slot to avoid conflicts with other contracts.
     * @return ds The storage structure for the initialized flag.
     */
    function initializedStorage() internal pure returns (InitializedS storage ds) {
        bytes32 position = INITIALIZED_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @notice Retrieves the storage for foreign calls.
     * @dev Uses a fixed storage slot to avoid conflicts with other contracts.
     * @return ds The storage structure for the foreign call map.
     */
    function getForeignCallStorage() internal pure returns (ForeignCallS storage ds) {
        bytes32 position = FOREIGN_CALL_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @notice Retrieves the storage for foreign call metadata.
     * @dev Uses a fixed storage slot to avoid conflicts with other contracts.
     * @return ds The storage structure for the foreign call metadata map.
     */
    function getForeignCallMetadataStorage() internal pure returns (ForeignCallMetadataStruct storage ds) {
        bytes32 position = FOREIGN_CALL_METADATA_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @notice Retrieves the storage for trackers.
     * @dev Uses a fixed storage slot to avoid conflicts with other contracts.
     * @return ds The storage structure for the tracker map.
     */
    function getTrackerStorage() internal pure returns (TrackerS storage ds) {
        bytes32 position = TRACKER_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @notice Retrieves the storage for tracker metadata.
     * @dev Uses a fixed storage slot to avoid conflicts with other contracts.
     * @return ds The storage structure for the tracker metadata map.
     */
    function getTrackerMetadataStorage() internal pure returns (TrackerMetadataStruct storage ds) {
        bytes32 position = TRACKER_METADATA_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @notice Retrieves the storage for function signatures.
     * @dev Uses a fixed storage slot to avoid conflicts with other contracts.
     * @return ds The storage structure for the function signature map.
     */
    function getFunctionSignatureStorage() internal pure returns (FunctionSignatureS storage ds) {
        bytes32 position = FUNCTION_SIGNATURE_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @notice Retrieves the storage for function signature metadata.
     * @dev Uses a fixed storage slot to avoid conflicts with other contracts.
     * @return ds The storage structure for the function signature metadata map.
     */
    function getFunctionSignatureMetadataStorage() internal pure returns (FunctionSignatureMetadataStruct storage ds) {
        bytes32 position = FUNCTION_SIGNATURE_METADATA_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @notice Retrieves the storage for rules.
     * @dev Uses a fixed storage slot to avoid conflicts with other contracts.
     * @return ds The storage structure for the rule map.
     */
    function getRuleStorage() internal pure returns (RuleS storage ds) {
        bytes32 position = RULE_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @notice Retrieves the storage for policies.
     * @dev Uses a fixed storage slot to avoid conflicts with other contracts.
     * @return ds The storage structure for the policy map.
     */
    function getPolicyStorage() internal pure returns (PolicyS storage ds) {
        bytes32 position = POLICY_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @notice Retrieves the storage for policy associations.
     * @dev Uses a fixed storage slot to avoid conflicts with other contracts.
     * @return ds The storage structure for the policy association map.
     */
    function getPolicyAssociationStorage() internal pure returns (PolicyAssociationS storage ds) {
        bytes32 position = POLICY_ASSOCIATION_POSITION;
        assembly {
            ds.slot := position
        }
    }

}
