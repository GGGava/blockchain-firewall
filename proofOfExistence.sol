pragma solidity ^0.4.25;

contract proofOfExistence {
    address owner;
    
     struct Registry{
        uint256 endTime;
        uint256 startTime;
        bool registred;
    }
    mapping(bytes32 => Registry) public packet;
    
    constructor() public {
        owner = msg.sender;
    }
    
    function pay(bytes32 hash, uint256 blocktime) payable public {
        require(packet[hash].registred == false);
        packet[hash].registred = true;
        packet[hash].startTime = blocktime + block.number;
        packet[hash].endTime = packet[hash].startTime + msg.value;
        owner.transfer(msg.value);
    }
    
    function verify(bytes32 hash) view public returns (bool){
        if (packet[hash].registred && block.number >= packet[hash].startTime && block.number <= packet[hash].endTime){
            return true;
        }
        return false;
    }
}