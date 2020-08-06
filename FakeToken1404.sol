pragma solidity 0.5.17;

library MessagesAndCodes {
    string public constant EMPTY_MESSAGE_ERROR = "Message cannot be empty string";
    string public constant CODE_RESERVED_ERROR = "Given code is already pointing to a message";
    string public constant CODE_UNASSIGNED_ERROR = "Given code does not point to a message";

    struct Data  {
        mapping (uint8 => string) messages;
        uint8[] codes;
    }

    function messageIsEmpty (string memory _message)
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

    function addMessage (Data storage self, uint8 _code, string memory _message)
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

    function autoAddMessage (Data storage self, string memory _message)
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

    function updateMessage (Data storage self, uint8 _code, string memory _message)
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

/**
 * @title SafeMath
 * @dev Math operations with safety checks that revert on error
 */
library SafeMath {
    int256 constant private INT256_MIN = -2**255;

    /**
    * @dev Multiplies two unsigned integers, reverts on overflow.
    */
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        // Gas optimization: this is cheaper than requiring 'a' not being zero, but the
        // benefit is lost if 'b' is also tested.
        // See: https://github.com/OpenZeppelin/openzeppelin-solidity/pull/522
        if (a == 0) {
            return 0;
        }

        uint256 c = a * b;
        require(c / a == b);

        return c;
    }

    /**
    * @dev Multiplies two signed integers, reverts on overflow.
    */
    function mul(int256 a, int256 b) internal pure returns (int256) {
        // Gas optimization: this is cheaper than requiring 'a' not being zero, but the
        // benefit is lost if 'b' is also tested.
        // See: https://github.com/OpenZeppelin/openzeppelin-solidity/pull/522
        if (a == 0) {
            return 0;
        }

        require(!(a == -1 && b == INT256_MIN)); // This is the only case of overflow not detected by the check below

        int256 c = a * b;
        require(c / a == b);

        return c;
    }

    /**
    * @dev Integer division of two unsigned integers truncating the quotient, reverts on division by zero.
    */
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        // Solidity only automatically asserts when dividing by 0
        require(b > 0);
        uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold

        return c;
    }

    /**
    * @dev Integer division of two signed integers truncating the quotient, reverts on division by zero.
    */
    function div(int256 a, int256 b) internal pure returns (int256) {
        require(b != 0); // Solidity only automatically asserts when dividing by 0
        require(!(b == -1 && a == INT256_MIN)); // This is the only case of overflow

        int256 c = a / b;

        return c;
    }

    /**
    * @dev Subtracts two unsigned integers, reverts on overflow (i.e. if subtrahend is greater than minuend).
    */
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a);
        uint256 c = a - b;

        return c;
    }

    /**
    * @dev Subtracts two signed integers, reverts on overflow.
    */
    function sub(int256 a, int256 b) internal pure returns (int256) {
        int256 c = a - b;
        require((b >= 0 && c <= a) || (b < 0 && c > a));

        return c;
    }

    /**
    * @dev Adds two unsigned integers, reverts on overflow.
    */
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a);

        return c;
    }

    /**
    * @dev Adds two signed integers, reverts on overflow.
    */
    function add(int256 a, int256 b) internal pure returns (int256) {
        int256 c = a + b;
        require((b >= 0 && c >= a) || (b < 0 && c < a));

        return c;
    }

    /**
    * @dev Divides two unsigned integers and returns the remainder (unsigned integer modulo),
    * reverts when dividing by zero.
    */
    function mod(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b != 0);
        return a % b;
    }
}

interface IERC1404 {
    /// @notice Detects if a transfer will be reverted and if so returns an appropriate reference code
    /// @param from Sending address
    /// @param to Receiving address
    /// @param value Amount of tokens being transferred
    /// @return Code by which to reference message for rejection reasoning
    /// @dev Overwrite with your custom transfer restriction logic
    function detectTransferRestriction (address from, address to, uint256 value) external view returns (uint8);

    /// @notice Returns a human-readable message for a given restriction code
    /// @param restrictionCode Identifier for looking up a message
    /// @return Text showing the restriction's reasoning
    /// @dev Overwrite with your custom message and restrictionCode handling
    function messageForTransferRestriction (uint8 restrictionCode) external view returns (string memory);
}

/**
 * @title ERC20 interface
 * @dev see https://github.com/ethereum/EIPs/issues/20
 */
interface IERC20 {
    function totalSupply() external view returns (uint256);

    function balanceOf(address who) external view returns (uint256);

    function allowance(address owner, address spender) external view returns (uint256);

    function transfer(address to, uint256 value) external returns (bool);

    function approve(address spender, uint256 value) external returns (bool);

    function transferFrom(address from, address to, uint256 value) external returns (bool);

    event Transfer(address indexed from, address indexed to, uint256 value);

    event Approval(address indexed owner, address indexed spender, uint256 value);
}

contract Owned {
    address public owner;
    
    mapping(address => bool) public managers;
    uint public managersCount = 0;

    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner, 'OWNER_IS_REQUIRED');
        _;
    }

    modifier onlyManager {
        require(managers[msg.sender] == true, 'MANAGER_IS_REQUIRED');
        _;
    }
    
    modifier onlyManagerOrOwner {
        require(msg.sender == owner || managers[msg.sender] == true, 'MANAGER_IS_REQUIRED');
        _;
    }
    
    function transferOwnership(address newOwner) onlyOwner public {
        owner = newOwner;
    }
    
    
    function addManager(address newManager) onlyOwner public {
        managers[newManager] = true;
        managersCount++;
    }
    
    function removeManager(address manager) onlyOwner public {
        managers[manager] = false;
        managersCount--;
    }
}

/**
 * @title Standard ERC20 token
 *
 * @dev Implementation of the basic standard token.
 * https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md
 * Originally based on code by FirstBlood: https://github.com/Firstbloodio/token/blob/master/smart_contract/FirstBloodToken.sol
 *
 * This implementation emits additional Approval events, allowing applications to reconstruct the allowance status for
 * all accounts just by listening to said events. Note that this isn't required by the specification, and other
 * compliant implementations may not do it.
 */
contract ERC20 is IERC20 {
    using SafeMath for uint256;
    
    /**
    * @dev This public variables for ERC20 token
    **/
    string public name;
    string public symbol;
    uint8 public decimals = 18;

    mapping (address => uint256) private _balances;

    mapping (address => mapping (address => uint256)) private _allowed;

    uint256 private _totalSupply;

    /**
    * @dev Total number of tokens in existence
    */
    function totalSupply() public view returns (uint256) {
        return _totalSupply;
    }

    /**
    * @dev Gets the balance of the specified address.
    * @param owner The address to query the balance of.
    * @return An uint256 representing the amount owned by the passed address.
    */
    function balanceOf(address owner) public view returns (uint256) {
        return _balances[owner];
    }

    /**
     * @dev Function to check the amount of tokens that an owner allowed to a spender.
     * @param owner address The address which owns the funds.
     * @param spender address The address which will spend the funds.
     * @return A uint256 specifying the amount of tokens still available for the spender.
     */
    function allowance(address owner, address spender) public view returns (uint256) {
        return _allowed[owner][spender];
    }

    /**
    * @dev Transfer token for a specified address
    * @param to The address to transfer to.
    * @param value The amount to be transferred.
    */
    function transfer(address to, uint256 value) public returns (bool) {
        _transfer(msg.sender, to, value);
        return true;
    }

    /**
     * @dev Approve the passed address to spend the specified amount of tokens on behalf of msg.sender.
     * Beware that changing an allowance with this method brings the risk that someone may use both the old
     * and the new allowance by unfortunate transaction ordering. One possible solution to mitigate this
     * race condition is to first reduce the spender's allowance to 0 and set the desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     * @param spender The address which will spend the funds.
     * @param value The amount of tokens to be spent.
     */
    function approve(address spender, uint256 value) public returns (bool) {
        require(spender != address(0));

        _allowed[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    /**
     * @dev Transfer tokens from one address to another.
     * Note that while this function emits an Approval event, this is not required as per the specification,
     * and other compliant implementations may not emit the event.
     * @param from address The address which you want to send tokens from
     * @param to address The address which you want to transfer to
     * @param value uint256 the amount of tokens to be transferred
     */
    function transferFrom(address from, address to, uint256 value) public returns (bool) {
        _allowed[from][msg.sender] = _allowed[from][msg.sender].sub(value);
        _transfer(from, to, value);
        emit Approval(from, msg.sender, _allowed[from][msg.sender]);
        return true;
    }

    /**
     * @dev Increase the amount of tokens that an owner allowed to a spender.
     * approve should be called when allowed_[_spender] == 0. To increment
     * allowed value is better to use this function to avoid 2 calls (and wait until
     * the first transaction is mined)
     * From MonolithDAO Token.sol
     * Emits an Approval event.
     * @param spender The address which will spend the funds.
     * @param addedValue The amount of tokens to increase the allowance by.
     */
    function increaseAllowance(address spender, uint256 addedValue) public returns (bool) {
        require(spender != address(0));

        _allowed[msg.sender][spender] = _allowed[msg.sender][spender].add(addedValue);
        emit Approval(msg.sender, spender, _allowed[msg.sender][spender]);
        return true;
    }

    /**
     * @dev Decrease the amount of tokens that an owner allowed to a spender.
     * approve should be called when allowed_[_spender] == 0. To decrement
     * allowed value is better to use this function to avoid 2 calls (and wait until
     * the first transaction is mined)
     * From MonolithDAO Token.sol
     * Emits an Approval event.
     * @param spender The address which will spend the funds.
     * @param subtractedValue The amount of tokens to decrease the allowance by.
     */
    function decreaseAllowance(address spender, uint256 subtractedValue) public returns (bool) {
        require(spender != address(0));

        _allowed[msg.sender][spender] = _allowed[msg.sender][spender].sub(subtractedValue);
        emit Approval(msg.sender, spender, _allowed[msg.sender][spender]);
        return true;
    }

    /**
    * @dev Transfer token for a specified addresses
    * @param from The address to transfer from.
    * @param to The address to transfer to.
    * @param value The amount to be transferred.
    */
    function _transfer(address from, address to, uint256 value) internal {
        require(to != address(0), "FORRBIDDEN_USE_BURN");
        require(_balances[from] >= value, "NOT_ENOUGH_TOKENS");
        _balances[from] = _balances[from].sub(value);
        _balances[to] = _balances[to].add(value);
        emit Transfer(from, to, value);
    }

    /**
     * @dev Internal function that mints an amount of the token and assigns it to
     * an account. This encapsulates the modification of balances such that the
     * proper events are emitted.
     * @param account The account that will receive the created tokens.
     * @param value The amount that will be created.
     */
    function _mint(address account, uint256 value) internal {
        require(account != address(0));

        _totalSupply = _totalSupply.add(value);
        _balances[account] = _balances[account].add(value);
        emit Transfer(address(0), account, value);
    }

    /**
     * @dev Internal function that burns an amount of the token of a given
     * account.
     * @param account The account whose tokens will be burnt.
     * @param value The amount that will be burnt.
     */
    function _burn(address account, uint256 value) internal {
        require(account != address(0));

        _totalSupply = _totalSupply.sub(value);
        _balances[account] = _balances[account].sub(value);
        emit Transfer(account, address(0), value);
    }

    /**
     * @dev Internal function that burns an amount of the token of a given
     * account, deducting from the sender's allowance for said account. Uses the
     * internal burn function.
     * Emits an Approval event (reflecting the reduced allowance).
     * @param account The account whose tokens will be burnt.
     * @param value The amount that will be burnt.
     */
    function _burnFrom(address account, uint256 value) internal {
        _allowed[account][msg.sender] = _allowed[account][msg.sender].sub(value);
        _burn(account, value);
        emit Approval(account, msg.sender, _allowed[account][msg.sender]);
    }
}

/**
 * @title Whitelist
 * @dev The Whitelist contract has a whitelist of addresses, and provides basic authorization control functions.
 * @dev This simplifies the implementation of "user permissions".
 */
contract Whitelist is Owned {
    
  mapping(address => bool) private _whitelist;
  
  event WhitelistedAddressAdded(address addr);
  event WhitelistedAddressRemoved(address addr);

  /**
   * @dev add an address to the whitelist
   * @param addr address
   * @return true if the address was added to the whitelist, false if the address was already in the whitelist 
   */
  function addAddressToWhitelist(address addr) onlyManagerOrOwner public returns(bool success) {
    if (!_whitelist[addr]) {
      _whitelist[addr] = true;
      emit WhitelistedAddressAdded(addr);
      success = true; 
    }
  }
  
  function whitelist(address addr) public view returns(bool success) {
      success = _whitelist[addr];
  }

  /**
   * @dev add addresses to the whitelist
   * @param addrs addresses
   * @return true if at least one address was added to the whitelist, 
   * false if all addresses were already in the whitelist  
   */
  function addAddressesToWhitelist(address[] memory addrs) onlyManagerOrOwner public returns(bool success) {
    for (uint256 i = 0; i < addrs.length; i++) {
      if (addAddressToWhitelist(addrs[i])) {
        success = true;
      }
    }
  }

  /**
   * @dev remove an address from the whitelist
   * @param addr address
   * @return true if the address was removed from the whitelist, 
   * false if the address wasn't in the whitelist in the first place 
   */
  function removeAddressFromWhitelist(address addr) onlyManagerOrOwner public returns(bool success) {
    if (_whitelist[addr]) {
      _whitelist[addr] = false;
      emit WhitelistedAddressRemoved(addr);
      success = true;
    }
  }

  /**
   * @dev remove addresses from the whitelist
   * @param addrs addresses
   * @return true if at least one address was removed from the whitelist, 
   * false if all addresses weren't in the whitelist in the first place
   */
  function removeAddressesFromWhitelist(address[] memory addrs) onlyOwner public returns(bool success) {
    for (uint256 i = 0; i < addrs.length; i++) {
      if (removeAddressFromWhitelist(addrs[i])) {
        success = true;
      }
    }
  }

}

/// @title Extendable reference implementation for the ERC-1404 token
/// @dev Inherit from this contract to implement your own ERC-1404 token
contract SimpleRestrictedToken is IERC1404, ERC20 {
    uint8 public constant SUCCESS_CODE = 0;
    string public constant SUCCESS_MESSAGE = "SUCCESS";

    modifier notRestricted (address from, address to, uint256 value) {
        uint8 restrictionCode = detectTransferRestriction(from, to, value);
        require(restrictionCode == SUCCESS_CODE, messageForTransferRestriction(restrictionCode));
        _;
    }
    
    function detectTransferRestriction (address /* from */, address /* to */, uint256 /* value */)
        public
        view
        returns (uint8 restrictionCode)
    {
        restrictionCode = SUCCESS_CODE;
    }
        
    function messageForTransferRestriction (uint8 restrictionCode)
        public
        view
        returns (string memory message)
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
        returns (string memory message)
    {
        message = messagesAndCodes.messages[restrictionCode];
    }
}

/**
 * @title Fake ERC1404 token
 *
 * @dev Implementation of the ERC1404 token.
 * https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md
 * Originally based on code by FirstBlood: https://github.com/Firstbloodio/token/blob/master/smart_contract/FirstBloodToken.sol
 *
 * This implementation emits additional Approval events, allowing applications to reconstruct the allowance status for
 * all accounts just by listening to said events. Note that this isn't required by the specification, and other
 * compliant implementations may not do it.
 */
contract FakeToken is MessagedERC1404, Whitelist {
    /**
    * @dev Restriction codes for erc1404
    */
    uint8 public NON_WHITELIST_CODE;
    string public constant NON_WHITELIST_ERROR = "ILLEGAL_TRANSFER_TO_NON_WHITELISTED_ADDRESS";

    /**
    * @dev Sell and buy prices for 1 token
    */
    uint256 public sellPrice = 10; 
    uint256 public buyPrice = 100;
    
    struct order 
    {
        uint256 blockNumber;
        uint256 quantity;
        uint256 timestamp;
        uint256 weiValue;
    }
    
    /**
     * @dev This create array with all transfers and prices
     */
    mapping (address => order[]) internal orders;
    
    constructor (string memory _name,
                string memory _symbol,
                uint256 _totalSupply) public 
    {
        decimals = 18; 
        NON_WHITELIST_CODE = messagesAndCodes.autoAddMessage(NON_WHITELIST_ERROR);
        name = _name;
        symbol =_symbol;
        _mint(address(this), _totalSupply * 10 ** uint256(decimals) );
    }

    /**
    * @dev Gets the number of orders.
    * @param buyer The address to query the orders of.
    * @return An uint256 representing the amount owned by the passed address.
    */
    function getOrdersNum(address buyer) external view returns (uint256)
    {
        return orders[buyer].length;
    }
    
    function getOrder(address buyer, uint index) external view returns (uint256, uint256, uint256, uint256) {
        require(orders[buyer].length > index, "INVALID_INDEX");
        return (orders[buyer][index].blockNumber, orders[buyer][index].quantity, orders[buyer][index].timestamp, orders[buyer][index].weiValue);
    }
    
    function() payable external {
        buy();
    }

    function burn(uint256 value) onlyOwner external
    {
        _burn(address(this), value);
    } 

    function detectTransferRestriction (address from, address to, uint /* value */)
        public
        view
        returns (uint8 restrictionCode)
    {
        if (!whitelist(to) && from == address(this)) {
            restrictionCode = NON_WHITELIST_CODE; // illegal transfer outside of whitelist
        } else {
            restrictionCode = SUCCESS_CODE; // successful transfer (required)
        }
    }
    
    /**
     * @notice Allow users to buy tokens for `newBuyPrice` eth and sell tokens for `newSellPrice` eth
     * @param newSellPrice Price the users can sell to the contract
     * @param newBuyPrice Price users can buy from the contract
     */
    function setPrices(uint256 newSellPrice, uint256 newBuyPrice) onlyOwner external {
        sellPrice = newSellPrice;
        buyPrice = newBuyPrice;
    }

    /**
     * @notice Buy tokens from contract by sending ether
     */
    function buy() notRestricted(address(this), msg.sender, msg.value) payable public
    {
        uint amount = msg.value * 10**18 / buyPrice;               // calculates the amount
        _transfer(address(this), msg.sender, amount);              // makes the transfers
        order memory currentOrder = order({                        // save order
            weiValue: msg.value,
            blockNumber: block.number,
            timestamp: now,
            quantity: amount
        });
        orders[msg.sender].push(currentOrder);
    }
    
     /**
     * @notice Buy tokens from contract by sending ether
     * @param to The address to get tokens
     */
    function buy(address to) notRestricted(address(this), to, msg.value) payable external
    {
        uint amount = msg.value * 10**18 / buyPrice;               // calculates the amount
        _transfer(address(this), to, amount);                      // makes the transfers
        order memory currentOrder = order({                        // save order
            weiValue: msg.value,
            blockNumber: block.number,
            timestamp: now,
            quantity: amount
        });
        orders[msg.sender].push(currentOrder);
    }
    
     /**
     * @notice Owner can withdraw ether
     * @param amount Ether amount to withdraw
     * @param to The address to get ether
     */
    function withdraw(uint amount, address payable to) onlyOwner external 
    {
        require(amount >= address(this).balance, 'NOT_ENOUGH_ETHER');
        address(to).transfer(amount);
    } 
    
    /**
     * @notice Sell `amount` tokens to contract
     * @param amount amount of tokens to be sold
     */
    function sell(uint256 amount) external 
    {
        require(address(this).balance >= amount * sellPrice / 10**18, "NOT_ENOUGH ETHER"); // checks if the contract has enough ether to buy
        _transfer(msg.sender, address(this), amount);                  // makes the transfers
        msg.sender.transfer(amount * sellPrice / 10**18);     // sends ether to the seller. It's important to do this last to avoid recursion attacks
    }
    
    
    /**
     * @notice Credited to the balance of the contract transferred ether
     */
    function topUp() external onlyManagerOrOwner payable {}
    
}


