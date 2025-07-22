// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;
import "src/engine/RulesEngineStorageStructure.sol";

/**
 * @title Rules Engine Storage Position Library
 * @dev This library provides functions to access and manage storage positions for various components of the Rules Engine.
 *      It defines fixed storage slots for initialized flags, foreign calls, trackers, calling functions, rules, policies,
 *      and policy associations. These storage slots are used to ensure consistent and conflict-free storage management
 *      across the diamond proxy pattern.
 * @notice This library is a critical component of the Rules Engine, enabling modular and efficient storage management.
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220
 */
library RulesEngineStoragePositionLib {
    bytes32 constant DIAMOND_CUT_STORAGE_ENGINE_POS = bytes32(uint256(keccak256("diamond-cut.storage-engine")) - 1);
    bytes32 constant INITIALIZED_POSITION = bytes32(uint256(keccak256("initialized-position")) - 1);
    bytes32 constant FOREIGN_CALL_POSITION = bytes32(uint256(keccak256("foreign-call-position")) - 1);
    bytes32 constant PERMISSIONED_FOREIGN_CALL_POSITION = bytes32(uint256(keccak256("permissioned-foreign-call-position")) - 1);
    bytes32 constant TRACKER_POSITION = bytes32(uint256(keccak256("tracker-position")) - 1);
    bytes32 constant CALLING_FUNCTION_POSITION = bytes32(uint256(keccak256("calling-function-position")) - 1);
    bytes32 constant RULE_POSITION = bytes32(uint256(keccak256("rule-position")) - 1);
    bytes32 constant POLICY_POSITION = bytes32(uint256(keccak256("policy-position")) - 1);
    bytes32 constant POLICY_ASSOCIATION_POSITION = bytes32(uint256(keccak256("policy-association-position")) - 1);
    bytes32 constant FOREIGN_CALL_METADATA_POSITION = bytes32(uint256(keccak256("foreign-call-metadata-position")) - 1);
    bytes32 constant CALLING_FUNCTION_METADATA_POSITION = bytes32(uint256(keccak256("calling-function-metadata-position")) - 1);
    bytes32 constant TRACKER_METADATA_POSITION = bytes32(uint256(keccak256("tracker-metadata-position")) - 1);
    bytes32 constant RULES_METADATA_POSITION = bytes32(uint256(keccak256("rules-metadata-position")) - 1);
    bytes32 constant POLICY_METADATA_POSITION = bytes32(uint256(keccak256("policy-metadata-position")) - 1);

    /**
     * @notice Retrieves the storage for the initialized flag.
     * @dev Uses a fixed storage slot to avoid conflicts with other contracts.
     * @return _ds The storage structure for the initialized flag.
     */
    function _initializedStorage() internal pure returns (InitializedStorage storage _ds) {
        bytes32 position = INITIALIZED_POSITION;
        assembly {
            _ds.slot := position
        }
    }

    /**
     * @notice Retrieves the storage for foreign calls.
     * @dev Uses a fixed storage slot to avoid conflicts with other contracts.
     * @return _ds The storage structure for the foreign call map.
     */
    function _getForeignCallStorage() internal pure returns (ForeignCallStorage storage _ds) {
        bytes32 position = FOREIGN_CALL_POSITION;
        assembly {
            _ds.slot := position
        }
    }

    /**
     * @notice Retrieves the storage for permissioned foreign calls.
     * @dev Uses a fixed storage slot to avoid conflicts with other contracts.
     * @return _ds The storage structure for the foreign call map.
     */
    function _getPermissionedForeignCallStorage() internal pure returns (PermissionedForeignCallStorage storage _ds) {
        bytes32 position = PERMISSIONED_FOREIGN_CALL_POSITION;
        assembly {
            _ds.slot := position
        }
    }

    /**
     * @notice Retrieves the storage for foreign call metadata.
     * @dev Uses a fixed storage slot to avoid conflicts with other contracts.
     * @return _ds The storage structure for the foreign call metadata map.
     */
    function _getForeignCallMetadataStorage() internal pure returns (ForeignCallMetadataStruct storage _ds) {
        bytes32 position = FOREIGN_CALL_METADATA_POSITION;
        assembly {
            _ds.slot := position
        }
    }

    /**
     * @notice Retrieves the storage for trackers.
     * @dev Uses a fixed storage slot to avoid conflicts with other contracts.
     * @return _ds The storage structure for the tracker map.
     */
    function _getTrackerStorage() internal pure returns (TrackerStorage storage _ds) {
        bytes32 position = TRACKER_POSITION;
        assembly {
            _ds.slot := position
        }
    }

    /**
     * @notice Retrieves the storage for tracker metadata.
     * @dev Uses a fixed storage slot to avoid conflicts with other contracts.
     * @return _ds The storage structure for the tracker metadata map.
     */
    function _getTrackerMetadataStorage() internal pure returns (TrackerMetadataStruct storage _ds) {
        bytes32 position = TRACKER_METADATA_POSITION;
        assembly {
            _ds.slot := position
        }
    }

    /**
     * @notice Retrieves the storage for calling functions.
     * @dev Uses a fixed storage slot to avoid conflicts with other contracts.
     * @return _ds The storage structure for the calling function map.
     */
    function _getCallingFunctionStorage() internal pure returns (CallingFunctionStruct storage _ds) {
        bytes32 position = CALLING_FUNCTION_POSITION;
        assembly {
            _ds.slot := position
        }
    }

    /**
     * @notice Retrieves the storage for calling function metadata.
     * @dev Uses a fixed storage slot to avoid conflicts with other contracts.
     * @return _ds The storage structure for the calling function metadata map.
     */
    function _getCallingFunctioneMetadataStorage() internal pure returns (CallingFunctionMetadataStruct storage _ds) {
        bytes32 position = CALLING_FUNCTION_METADATA_POSITION;
        assembly {
            _ds.slot := position
        }
    }

    /**
     * @notice Retrieves the storage for rules.
     * @dev Uses a fixed storage slot to avoid conflicts with other contracts.
     * @return _ds The storage structure for the rule map.
     */
    function _getRuleStorage() internal pure returns (RuleStorage storage _ds) {
        bytes32 position = RULE_POSITION;
        assembly {
            _ds.slot := position
        }
    }

    /**
     * @notice Retrieves the storage for rules metadata.
     * @dev Uses a fixed storage slot to avoid conflicts with other contracts.
     * @return _ds The storage structure for the rules metadata map.
     */
    function _getRulesMetadataStorage() internal pure returns (RulesMetadataStruct storage _ds) {
        bytes32 position = RULES_METADATA_POSITION;
        assembly {
            _ds.slot := position
        }
    }

    /**
     * @notice Retrieves the storage for policies.
     * @dev Uses a fixed storage slot to avoid conflicts with other contracts.
     * @return _ds The storage structure for the policy map.
     */
    function _getPolicyStorage() internal pure returns (PolicyStorage storage _ds) {
        bytes32 position = POLICY_POSITION;
        assembly {
            _ds.slot := position
        }
    }

    /**
     * @notice Retrieves the storage for policy metadata.
     * @dev Uses a fixed storage slot to avoid conflicts with other contracts.
     * @return _ds The storage structure for the policy metadata map.
     */
    function _getPolicyMetadataStorage() internal pure returns (PolicyMetadataStruct storage _ds) {
        bytes32 position = POLICY_METADATA_POSITION;
        assembly {
            _ds.slot := position
        }
    }

    /**
     * @notice Retrieves the storage for policy associations.
     * @dev Uses a fixed storage slot to avoid conflicts with other contracts.
     * @return _ds The storage structure for the policy association map.
     */
    function _getPolicyAssociationStorage() internal pure returns (PolicyAssociationStorage storage _ds) {
        bytes32 position = POLICY_ASSOCIATION_POSITION;
        assembly {
            _ds.slot := position
        }
    }
}
