import time
import unittest

from ai_audits.contract_provider import ValidatorTemplate, ValidatorTemplateError


__all__ = ['ValidatorTemplateTestCase']


CONTRACT_TEMPLATE = '''
contract Wallet_<|timestamp|> {
    mapping (address => uint) <|random:userBalance|balance|userTokens|tokens|data|store|funds|a|b|c|>;
   
    function getBalance(address u) constant returns(uint){
        return <|random:userBalance|balance|userTokens|tokens|data|store|funds|a|b|c|>[u];
    }

    function addToBalance() payable{
        <|random:userBalance|balance|userTokens|tokens|data|store|funds|a|b|c|>[msg.sender] += msg.value;
    }   

    function withdrawBalance(){
        // send <|random:userBalance|balance|userTokens|tokens|data|store|funds|a|b|c|>[msg.sender] ethers to msg.sender
        // if mgs.sender is a contract, it will call its fallback function
        if( ! (msg.sender.call.value(<|random:userBalance|balance|userTokens|tokens|data|store|funds|a|b|c|>[msg.sender])() ) ){
            throw;
        }
        <|random:userBalance|balance|userTokens|tokens|data|store|funds|a|b|c|>[msg.sender] = 0;
    }   
}
'''

CONTRACT_EXAMPLE = '''
contract Wallet_1 {
    mapping (address => uint) userBalance;
   
    function getBalance(address u) constant returns(uint){
        return userBalance[u];
    }

    function addToBalance() payable{
        userBalance[msg.sender] += msg.value;
    }   

    function withdrawBalance(){
        // send userBalance[msg.sender] ethers to msg.sender
        // if mgs.sender is a contract, it will call its fallback function
        if( ! (msg.sender.call.value(userBalance[msg.sender])() ) ){
            throw;
        }
        userBalance[msg.sender] = 0;
    }   
}
'''


class ValidatorTemplateTestCase(unittest.TestCase):
    def test_find_replacements(self):
        tpl = ValidatorTemplate()
        replacements = tpl.find_replacements(CONTRACT_TEMPLATE)
        self.assertEqual(len(replacements), 2)
        self.assertEqual({x['method'] for x in replacements}, {'timestamp', 'random'})
        by_method = {x['method']: x for x in replacements}
        self.assertEqual(by_method['timestamp']['pattern'], '<|timestamp|>')
        self.assertEqual(
            by_method['random']['pattern'],
            '<|random:userBalance|balance|userTokens|tokens|data|store|funds|a|b|c|>'
        )
        self.assertEqual(by_method['timestamp']['arguments'], [])
        self.assertEqual(
            by_method['random']['arguments'],
            ['userBalance', 'balance', 'userTokens', 'tokens', 'data', 'store', 'funds', 'a', 'b', 'c']
        )
        current_time = int(time.time())
        self.assertIn(
            by_method['timestamp']['replacement'],
            [f'{current_time - 1}', f'{current_time}', f'{current_time + 1}']
        )
        self.assertIn(by_method['random']['replacement'], by_method['random']['arguments'])

    def test_apply_replacements(self):
        replacements = [
            {
                'arguments': [
                    'userBalance', 'balance', 'userTokens', 'tokens', 'data', 'store', 'funds', 'a', 'b', 'c'
                ],
                'pattern': '<|random:userBalance|balance|userTokens|tokens|data|store|funds|a|b|c|>',
                'method': 'random',
                'replacement': 'userBalance'
            },
            {'arguments': [], 'pattern': '<|timestamp|>', 'method': 'timestamp', 'replacement': '1'}
        ]
        contract = ValidatorTemplate.apply_replacements(CONTRACT_TEMPLATE, replacements)
        self.assertEqual(contract, CONTRACT_EXAMPLE)

    def test_error(self):
        tpl = ValidatorTemplate()
        with self.assertRaises(ValidatorTemplateError):
            tpl.find_replacements('contract <|unknown|>')
