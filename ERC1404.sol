pragma solidity ^0.4.26;


library MessagesAndCodes {
    string public constant EMPTY_MESSAGE_ERROR = "Message cannot be empty string";
    string public constant CODE_RESERVED_ERROR = "Given code is already pointing to a message";
    string public constant CODE_UNASSIGNED_ERROR = "Given code does not point to a message";

    struct Data {
        mapping (uint8 => string) messages;
        uint8[] codes;
    }

    function messageIsEmpty (string _message)
        internal
        pure
        returns (bool isEmpty)
    {
        isEmpty = bytes(_message).length == 0;
    }

    function messageExists (Data storage self, uint8 _code)
        internal
        view
        returns (bool exists)
    {
        exists = bytes(self.messages[_code]).length > 0;
    }

    function addMessage (Data storage self, uint8 _code, string _message)
        public
        returns (uint8 code)
    {
        require(!messageIsEmpty(_message), EMPTY_MESSAGE_ERROR);
        require(!messageExists(self, _code), CODE_RESERVED_ERROR);

        // enter message at code and push code onto storage
        self.messages[_code] = _message;
        self.codes.push(_code);
        code = _code;
    }

    function autoAddMessage (Data storage self, string _message)
        public
        returns (uint8 code)
    {
        require(!messageIsEmpty(_message), EMPTY_MESSAGE_ERROR);

        // find next available code to store the message at
        code = 0;
        while (messageExists(self, code)) {
            code++;
        }

        // add message at the auto-generated code
        addMessage(self, code, _message);
    }

    function removeMessage (Data storage self, uint8 _code)
        public
        returns (uint8 code)
    {
        require(messageExists(self, _code), CODE_UNASSIGNED_ERROR);

        // find index of code
        uint8 indexOfCode = 0;
        while (self.codes[indexOfCode] != _code) {
            indexOfCode++;
        }

        // remove code from storage by shifting codes in array
        for (uint8 i = indexOfCode; i < self.codes.length - 1; i++) {
            self.codes[i] = self.codes[i + 1];
        }
        self.codes.length--;

        // remove message from storage
        self.messages[_code] = "";
        code = _code;
    }

    function updateMessage (Data storage self, uint8 _code, string _message)
        public
        returns (uint8 code)
    {
        require(!messageIsEmpty(_message), EMPTY_MESSAGE_ERROR);
        require(messageExists(self, _code), CODE_UNASSIGNED_ERROR);

        // update message at code
        self.messages[_code] = _message;
        code = _code;
    }
}

library SafeMathLib {
  function times(uint a, uint b) returns (uint) {
    uint c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function minus(uint a, uint b) returns (uint) {
    assert(b <= a);
    return a - b;
  }

  function plus(uint a, uint b) returns (uint) {
    uint c = a + b;
    assert(c>=a && c>=b);
    return c;
  }

  function assert(bool assertion) private {
    if (!assertion) throw;
  }
}

library ERC20Lib {
  using SafeMathLib for uint;

  struct TokenStorage {
    mapping (address => uint) balances;
    mapping (address => mapping (address => uint)) allowed;
    uint totalSupply;
  }

  event Transfer(address indexed from, address indexed to, uint value);
  event Approval(address indexed owner, address indexed spender, uint value);

  function init(TokenStorage storage self, uint _initial_supply) {
    self.totalSupply = _initial_supply;
    self.balances[msg.sender] = _initial_supply;
  }

  function transfer(TokenStorage storage self, address _to, uint _value) returns (bool success) {
    self.balances[msg.sender] = self.balances[msg.sender].minus(_value);
    self.balances[_to] = self.balances[_to].plus(_value);
    Transfer(msg.sender, _to, _value);
    return true;
  }

  function transferFrom(TokenStorage storage self, address _from, address _to, uint _value) returns (bool success) {
    var _allowance = self.allowed[_from][msg.sender];

    self.balances[_to] = self.balances[_to].plus(_value);
    self.balances[_from] = self.balances[_from].minus(_value);
    self.allowed[_from][msg.sender] = _allowance.minus(_value);
    Transfer(_from, _to, _value);
    return true;
  }

  function balanceOf(TokenStorage storage self, address _owner) constant returns (uint balance) {
    return self.balances[_owner];
  }

  function approve(TokenStorage storage self, address _spender, uint _value) returns (bool success) {
    self.allowed[msg.sender][_spender] = _value;
    Approval(msg.sender, _spender, _value);
    return true;
  }

  function allowance(TokenStorage storage self, address _owner, address _spender) constant returns (uint remaining) {
    return self.allowed[_owner][_spender];
  }
}

interface ERC20 {
    function transferFrom(address _from, address _to, uint _value) public returns (bool);
    function approve(address _spender, uint _value) public returns (bool);
    function allowance(address _owner, address _spender) public constant returns (uint);
    event Approval(address indexed _owner, address indexed _spender, uint _value);
}

/**
 * Standard ERC20 token
 *
 * https://github.com/ethereum/EIPs/issues/20
 * Based on code by FirstBlood:
 * https://github.com/Firstbloodio/token/blob/master/smart_contract/FirstBloodToken.sol
 */
 contract StandardToken {
   using ERC20Lib for ERC20Lib.TokenStorage;

   ERC20Lib.TokenStorage token;

   string public name = "SimpleToken";
   string public symbol = "SIM";
   uint public decimals = 18;
   uint public INITIAL_SUPPLY = 10000;

   function StandardToken() {
     token.init(INITIAL_SUPPLY);
   }

   function totalSupply() constant returns (uint) {
     return token.totalSupply;
   }

   function balanceOf(address who) constant returns (uint) {
     return token.balanceOf(who);
   }

   function allowance(address owner, address spender) constant returns (uint) {
     return token.allowance(owner, spender);
   }

   function transfer(address to, uint value) returns (bool ok) {
     return token.transfer(to, value);
   }

   function transferFrom(address from, address to, uint value) returns (bool ok) {
     return token.transferFrom(from, to, value);
   }

   function approve(address spender, uint value) returns (bool ok) {
     return token.approve(spender, value);
   }

   event Transfer(address indexed from, address indexed to, uint value);
   event Approval(address indexed owner, address indexed spender, uint value);
 }

contract ERC1404 is ERC20 {
    /// @notice Detects if a transfer will be reverted and if so returns an appropriate reference code
    /// @param from Sending address
    /// @param to Receiving address
    /// @param value Amount of tokens being transferred
    /// @return Code by which to reference message for rejection reasoning
    /// @dev Overwrite with your custom transfer restriction logic
    function detectTransferRestriction (address from, address to, uint256 value) public view returns (uint8);

    /// @notice Returns a human-readable message for a given restriction code
    /// @param restrictionCode Identifier for looking up a message
    /// @return Text showing the restriction's reasoning
    /// @dev Overwrite with your custom message and restrictionCode handling
    function messageForTransferRestriction (uint8 restrictionCode) public view returns (string);
}

/// @title Extendable reference implementation for the ERC-1404 token
/// @dev Inherit from this contract to implement your own ERC-1404 token
contract SimpleRestrictedToken is ERC1404, StandardToken {
    uint8 public constant SUCCESS_CODE = 0;
    string public constant SUCCESS_MESSAGE = "SUCCESS";

    modifier notRestricted (address from, address to, uint256 value) {
        uint8 restrictionCode = detectTransferRestriction(from, to, value);
        require(restrictionCode == SUCCESS_CODE, messageForTransferRestriction(restrictionCode));
        _;
    }
    
    function detectTransferRestriction (address from, address to, uint256 value)
        public
        view
        returns (uint8 restrictionCode)
    {
        restrictionCode = SUCCESS_CODE;
    }
        
    function messageForTransferRestriction (uint8 restrictionCode)
        public
        view
        returns (string message)
    {
        if (restrictionCode == SUCCESS_CODE) {
            message = SUCCESS_MESSAGE;
        }
    }
    
    function transfer (address to, uint256 value)
        public
        notRestricted(msg.sender, to, value)
        returns (bool success)
    {
        success = super.transfer(to, value);
    }

    function transferFrom (address from, address to, uint256 value)
        public
        notRestricted(from, to, value)
        returns (bool success)
    {
        success = super.transferFrom(from, to, value);
    }
}


/// @title ERC-1404 implementation with built-in message and code management solution
/// @dev Inherit from this contract to implement your own ERC-1404 token
contract MessagedERC1404 is SimpleRestrictedToken {
    using MessagesAndCodes for MessagesAndCodes.Data;
    MessagesAndCodes.Data internal messagesAndCodes;

    constructor () public {
        messagesAndCodes.addMessage(SUCCESS_CODE, SUCCESS_MESSAGE);
    }

    function messageForTransferRestriction (uint8 restrictionCode)
        public
        view
        returns (string message)
    {
        message = messagesAndCodes.messages[restrictionCode];
    }
}
