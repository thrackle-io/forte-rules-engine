// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;
import "src/engine/RulesEngineStorageStructure.sol";

/**
 * @title Rules Engine Storage Library
 * @author @ShaneDuncan602
 * @dev This contract serves as the storage library for the rules engine. It serves up the storage position for all storage data
 * @notice Library for Rules Engine
 */
library RulesEngineStoragePositionLib {
    bytes32 constant DIAMOND_CUT_STORAGE_ENGINE_POS =
        bytes32(uint256(keccak256("diamond-cut.storage-engine")) - 1);
    bytes32 constant INITIALIZED_POSITION =
        bytes32(uint256(keccak256("initialized-position")) - 1);
    bytes32 constant FOREIGN_CALL_POSITION =
        bytes32(uint256(keccak256("foreign-call-position")) - 1);
    bytes32 constant TRACKER_POSITION =
        bytes32(uint256(keccak256("tracker-position")) - 1);
    bytes32 constant FUNCTION_SIGNATURE_POSITION =
        bytes32(uint256(keccak256("function-signature-position")) - 1);
    bytes32 constant RULE_POSITION =
        bytes32(uint256(keccak256("rule-position")) - 1);
    bytes32 constant POLICY_POSITION =
        bytes32(uint256(keccak256("policy-position")) - 1);
    bytes32 constant POLICY_ASSOCIATION_POSITION =
        bytes32(uint256(keccak256("policy-association-position")) - 1);

    /**
     * @dev Function to store the Initialized flag
     * @return ds Data Storage of the Initialized flag
     */
    function initializedStorage()
        internal
        pure
        returns (InitializedS storage ds)
    {
        bytes32 position = INITIALIZED_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @dev Function to retrieve Foreign Call Storage from its diamond storage slot
     * @return ds Data Storage of the Foreign Call Map
     */
    function getForeignCallStorage()
        internal
        pure
        returns (ForeignCallS storage ds)
    {
        bytes32 position = FOREIGN_CALL_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @dev Function to retrieve Tracker Storage from its diamond storage slot
     * @return ds Data Storage of the Tracker Map
     */
    function getTrackerStorage() internal pure returns (TrackerS storage ds) {
        bytes32 position = TRACKER_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @dev Function to retrieve Function Signature Storage from its diamond storage slot
     * @return ds Data Storage of the Function Signature Map
     */
    function getFunctionSignatureStorage()
        internal
        pure
        returns (FunctionSignatureS storage ds)
    {
        bytes32 position = FUNCTION_SIGNATURE_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @dev Function to retrieve Rule Storage from its diamond storage slot
     * @return ds Data Storage of the Rule Map
     */
    function getRuleStorage() internal pure returns (RuleS storage ds) {
        bytes32 position = RULE_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @dev Function to retrieve Policy Storage from its diamond storage slot
     * @return ds Data Storage of the Policy Map
     */
    function getPolicyStorage() internal pure returns (PolicyS storage ds) {
        bytes32 position = POLICY_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @dev Function to retrieve Policy Association Storage from its diamond storage slot
     * @return ds Data Storage of the Policy Association Map
     */
    function getPolicyAssociationStorage()
        internal
        pure
        returns (PolicyAssociationS storage ds)
    {
        bytes32 position = POLICY_ASSOCIATION_POSITION;
        assembly {
            ds.slot := position
        }
    }

}
