// SPDX-License-Identifier: MIT
//
// ERC1820 Pseudo-introspection Registry Contract
// (ported to solc 0.8.x — identical logic to the canonical 0.5.3 registry by
//  Jordi Baylina & Jacques Dafflon; CC0. This is chain infrastructure we
//  re-compile and install at the canonical address for the range; the protocol
//  under test is the Uniswap-V1 pool + the unmodified OZ ERC-777 token.)
//
// This standard defines a universal registry smart contract where any address
// (contract or regular account) can register which interface it supports and
// which smart contract is responsible for its implementation.
pragma solidity ^0.8.24;

/// @dev The interface a contract MUST implement if it is the implementer of
///      some (other) interface for any address other than itself.
interface ERC1820ImplementerInterface {
    function canImplementInterfaceForAddress(bytes32 interfaceHash, address addr)
        external
        view
        returns (bytes32);
}

/// @title ERC1820 Pseudo-introspection Registry Contract
/// @notice Official implementation of the ERC1820 Registry.
contract ERC1820Registry {
    bytes4 internal constant INVALID_ID = 0xffffffff;
    bytes4 internal constant ERC165ID = 0x01ffc9a7;
    bytes32 internal constant ERC1820_ACCEPT_MAGIC = keccak256(abi.encodePacked("ERC1820_ACCEPT_MAGIC"));

    /// @notice mapping from addresses and interface hashes to their implementers.
    mapping(address => mapping(bytes32 => address)) internal interfaces;
    /// @notice mapping from addresses to their manager.
    mapping(address => address) internal managers;
    /// @notice flag for each address and erc165 interface to indicate if it is cached.
    mapping(address => mapping(bytes4 => bool)) internal erc165Cached;

    event InterfaceImplementerSet(address indexed addr, bytes32 indexed interfaceHash, address indexed implementer);
    event ManagerChanged(address indexed addr, address indexed newManager);

    /// @notice Query if an address implements an interface and through which contract.
    function getInterfaceImplementer(address _addr, bytes32 _interfaceHash) external view returns (address) {
        address addr = _addr == address(0) ? msg.sender : _addr;
        if (isERC165Interface(_interfaceHash)) {
            bytes4 erc165InterfaceHash = bytes4(_interfaceHash);
            return implementsERC165Interface(addr, erc165InterfaceHash) ? addr : address(0);
        }
        return interfaces[addr][_interfaceHash];
    }

    /// @notice Sets the contract which implements a specific interface for an address.
    function setInterfaceImplementer(address _addr, bytes32 _interfaceHash, address _implementer) external {
        address addr = _addr == address(0) ? msg.sender : _addr;
        require(getManager(addr) == msg.sender, "Not the manager");

        require(!isERC165Interface(_interfaceHash), "Must not be an ERC165 hash");
        if (_implementer != address(0) && _implementer != msg.sender) {
            require(
                ERC1820ImplementerInterface(_implementer).canImplementInterfaceForAddress(_interfaceHash, addr)
                    == ERC1820_ACCEPT_MAGIC,
                "Does not implement the interface"
            );
        }
        interfaces[addr][_interfaceHash] = _implementer;
        emit InterfaceImplementerSet(addr, _interfaceHash, _implementer);
    }

    /// @notice Sets '_newManager' as manager for '_addr'.
    function setManager(address _addr, address _newManager) external {
        require(getManager(_addr) == msg.sender, "Not the manager");
        managers[_addr] = _newManager == _addr ? address(0) : _newManager;
        emit ManagerChanged(_addr, _newManager);
    }

    /// @notice Get the manager of an address.
    function getManager(address _addr) public view returns (address) {
        if (managers[_addr] == address(0)) {
            return _addr;
        } else {
            return managers[_addr];
        }
    }

    /// @notice Compute the keccak256 hash of an interface given its name.
    function interfaceHash(string calldata _interfaceName) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(_interfaceName));
    }

    /* --- ERC165 Related Functions --- */

    function updateERC165Cache(address _contract, bytes4 _interfaceId) external {
        interfaces[_contract][_interfaceId] = implementsERC165InterfaceNoCache(_contract, _interfaceId)
            ? _contract
            : address(0);
        erc165Cached[_contract][_interfaceId] = true;
    }

    function implementsERC165Interface(address _contract, bytes4 _interfaceId) public view returns (bool) {
        if (!erc165Cached[_contract][_interfaceId]) {
            return implementsERC165InterfaceNoCache(_contract, _interfaceId);
        }
        return interfaces[_contract][_interfaceId] == _contract;
    }

    function implementsERC165InterfaceNoCache(address _contract, bytes4 _interfaceId) public view returns (bool) {
        uint256 success;
        uint256 result;

        (success, result) = noThrowCall(_contract, ERC165ID);
        if (success == 0 || result == 0) {
            return false;
        }

        (success, result) = noThrowCall(_contract, INVALID_ID);
        if (success == 0 || result != 0) {
            return false;
        }

        (success, result) = noThrowCall(_contract, _interfaceId);
        if (success == 1 && result == 1) {
            return true;
        }
        return false;
    }

    /// @dev Checks whether the hash is a ERC165 interface (ending with 28 zeroes) or not.
    function isERC165Interface(bytes32 _interfaceHash) internal pure returns (bool) {
        return _interfaceHash & 0x00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF == 0;
    }

    /// @dev Make a call on a contract without throwing if the function does not exist.
    function noThrowCall(address _contract, bytes4 _interfaceId)
        internal
        view
        returns (uint256 success, uint256 result)
    {
        bytes4 erc165ID = ERC165ID;

        assembly {
            let x := mload(0x40)
            mstore(x, erc165ID)
            mstore(add(x, 0x04), _interfaceId)

            success := staticcall(30000, _contract, x, 0x24, x, 0x20)

            result := mload(x)
        }
    }
}
