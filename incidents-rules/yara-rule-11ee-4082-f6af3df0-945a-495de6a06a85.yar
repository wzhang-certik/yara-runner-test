rule Always_mint_defaultAmount_token_when_user_balance_is_0
{
    meta:
        version = "2023-02-02:6bda31619fb6a4ecb4c456b4165a3daf732d64ab"
        rule_description = "This is a rule to detect mint defaultAmount of token when the caller's balance is 0"
        example_link = "https://accelerator.audit.certikpowered.info/project/2c9e5380-f203-11ec-8973-95f264a44484/findings?fid=1658986459970"
        loc_condition = "$function_identifier"
        category = "Logical Issue"
        severity = "critical"
        title = "Always mint `_defaultAmount` token when user's balance is 0"
        description = "In the **[fixme - add contract name]** contract, the `_beforeTokenTransfer(address,address,uint256)` and `_afterTokenTransfer(address,address,uint256)` of the standard ERC20 `transfer` logic will always mint `_defaultAmount` of `FavorToken` to the corresponding account whose balance is 0. Thus, malicious users can keep calling the function `transfer()` to mint an unlimited number of `FavorToken`."
        recommendation = "We recommend just reverting the transaction when either of the balances of `from` or `to` is 0."
        author = "xiaogang.hu@certik.com"
        trigger_mode = "logical issue"
    strings:
        $function_identifier = /function _(before|after)TokenTransfer\(/

        $req1 = /balances = _balanceOf\((from|to), false\);\n.{,20}if \(balances == (amount|0)\) {\n.{,20}_mint\((from|to), _defaultAmount\);/

    condition:
        $function_identifier
        and $req1
}