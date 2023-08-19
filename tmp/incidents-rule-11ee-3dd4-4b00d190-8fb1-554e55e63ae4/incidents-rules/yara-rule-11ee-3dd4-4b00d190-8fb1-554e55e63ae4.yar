rule Incorrect_variable_usage
{
    meta:
        version = "2023-02-21:53ca295966903b9f1f638a6b08b52271d02c92c6"
        rule_description = "This is a rule that detects the function deposit that can be overwritten."
        example_link = "https://accelerator.audit.certikpowered.info/project/7e331e10-e501-11ec-be2d-8b7f836b737c/findings?fid=1658609028419"
        loc_condition = "$in_1"
        category = "Logical Issue"
        severity = "major"
        title = "Incorrect Variable Usage"
        description = "The function **[fixme: function name]** receives payment from `msg.sender` and mint NFT tokens to the account, at the indicated location `require(msg.value>=DEV_MINT_PRICE*quantity)` should be used instead of `require(msg.value>=DEV_MINT_LIMIT*quantity)` for the payment check. "
        recommendation = "We advise the client to recheck the function and perform corresponding changes."
        author = "xiaogang.hu@certik.com"
    strings:
        // $fun_identifier = /function devMint\(\n{,1}(.{,100},\n{,1})*.{,100}\n{,1}.{,100}\)\s\n{,1}(external|public).{,100}{\n{,1}/i
        $in_1 = "DEV_MINT_LIMIT*quantity"
 
    condition:
        // $fun_identifier
        $in_1
}