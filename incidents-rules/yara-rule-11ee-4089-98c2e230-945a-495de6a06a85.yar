rule Blacklist_Can_Be_Bypassed
{
    meta:
        rule_description = "This is a PoC rule to detect the ability to bypass a token blacklist feature through a combination of `approve()` and `transferFrom()`."
        example_link = "https://acc.audit.certikpowered.info/project/533466b0-8043-11ec-a265-439950cfe98b/findings?fid=1644280977329"
        loc_condition = "$fun_transfer"
        category = "Logical Issue"
        severity = "major"
        title = "Potential Bypass of Blacklisted Users"
        description = "The blacklist feature is designed to prevent the blacklisted users from transferring the **[FIXME - Token Name]** to others by validating the following **require** statement **[FIXME - Add the require statement in the `transferFrom()` that checks the `msg.sender` is not blacklisted.]**. The **require** statement prohibits the blacklisted users from calling `transfer()` and `transferFrom()` to move their funds by requiring the `msg.sender` not blacklisted. However, this feature can be bypassed by using a combination of the `approve()`/`increaseAllowance()` and `transferFrom()` functions. The blacklisted user could approve another account to transfer his tokens on his behalf."
        recommendation = "We recommend validating the `msg.sender` is not blacklisted in the function `approve()`. Or we recommend checking the `from` address is not blacklisted in the function `transferFrom()`."
        author = "wilson.wu@certik.com"
    strings:
        // `approve()` function idetnfiier
        $fun_approve = /function approve\s*\([a-zA-Z0-9,_\n ]{1,200}\)/ nocase
        // `increaseAllowance()` function idetnfiier
        $fun_increase_allowance = /function (increaseAllowance|increaseApproval)\s*\([a-zA-Z0-9,_\n ]{1,200}\)/ nocase
        // `transferFrom()` function identifier
        $fun_transfer = /function transferFrom\s*\([a-zA-Z0-9,_\n ]{1,200}\)/ nocase
        // `_beforeTokenTransfer()` function identifier
        $fun_beforeTokenTransfer = /function _?beforeTokenTransfer\s*\([a-zA-Z0-9,_\n ]{1,200}\)/ nocase
        // `_afterTokenTransfer()` function identifier
        $fun_afterTokenTransfer = /function _?afterTokenTransfer\s*\([a-zA-Z0-9,_\n ]{1,200}\)/ nocase
        
        // Include some sort of blacklist/blocklist in $fun_beforeTokenTransfer or $fun_afterTokenTransfer functions
        $blacklist = /(blacklist|blocklist)[a-zA-Z_\[\]\(\)]{0,50}msg\.sender *\]/ nocase
        $blacklist_from = /(blacklist|blocklist)[a-zA-Z_\[\]\(\)]{0,50}(from|sender) *\]/ nocase

        // End position
        $block_str = /(function|modifier|contract)\s/

    condition:
        $blacklist
        and(
            (
                for any i in (1 .. #fun_beforeTokenTransfer) : (
                    (        
                        // Check for blacklist usage in `beforeTokenTransfer()` function
                        (
                            $blacklist in (@fun_beforeTokenTransfer[i] .. @block_str[#block_str in (0 .. @fun_beforeTokenTransfer[i]) + 1])
                            and not $blacklist_from in (@fun_beforeTokenTransfer[i] .. @block_str[#block_str in (0 .. @fun_beforeTokenTransfer[i]) + 1])
                        )
                        or(  
                            #block_str in (0 .. @fun_beforeTokenTransfer[i]) == #block_str
                            and 
                            (
                                $blacklist in (@fun_beforeTokenTransfer[i] .. filesize)
                                and not  $blacklist_from in (@fun_beforeTokenTransfer[i] .. filesize)
                            )
                        )
                        
                    )
                )
            )
            or
            (
                for any i in (1 .. #fun_afterTokenTransfer) : (
                    (        
                        // Check for blacklist usage in `afterTokenTransfer()` function
                        (
                            $blacklist in (@fun_afterTokenTransfer[i] .. @block_str[#block_str in (0 .. @fun_afterTokenTransfer[i]) + 1])
                            and not $blacklist_from in (@fun_afterTokenTransfer[i] .. @block_str[#block_str in (0 .. @fun_afterTokenTransfer[i]) + 1])
                        )
                        or(  
                            #block_str in (0 .. @fun_afterTokenTransfer[i]) == #block_str
                            and 
                            (
                                $blacklist in (@fun_afterTokenTransfer[i] .. filesize)
                                and not  $blacklist_from in (@fun_afterTokenTransfer[i] .. filesize)
                            )
                        )
                        
                    )
                )
            )
            or
            (
                for any i in (1 .. #fun_transfer) : (
                    (        
                        // Check for blacklist usage either external/internal `transfer()` function
                        (
                            $blacklist in (@fun_transfer[i] .. @block_str[#block_str in (0 .. @fun_transfer[i]) + 1])
                            and not $blacklist_from in (@fun_transfer[i] .. @block_str[#block_str in (0 .. @fun_transfer[i]) + 1])
                        )
                        or(  
                            #block_str in (0 .. @fun_transfer[i]) == #block_str
                            and 
                            (
                                $blacklist in (@fun_transfer[i] .. filesize)
                                and not  $blacklist_from in (@fun_transfer[i] .. filesize)
                            )
                        )
                        
                    )
                )
            )
        )
        and 
        (
            (
                // Functions `approve()` and `increaseAllowance()` do not exist in the contract
                not $fun_increase_allowance and not $fun_approve
            )
            or
            (
                // Or `approve()` does exist in the contract. Ensure it is not using the blacklist
                $fun_approve 
                and for any i in (1 .. #fun_approve) : (
                    (
                        not $blacklist in (@fun_approve[i] .. @block_str[#block_str in (0 .. @fun_approve[i]) + 1])
                        or
                        (#block_str in (0 .. @fun_approve[i]) == #block_str
                        and not $blacklist in (@fun_approve[i] .. filesize))
                    )
                )
            )
            or
            (
                // Or `increaseAllowance()` does exist in the contract. Ensure it is not using the blacklist
                $fun_increase_allowance 
                and for any i in (1 .. #fun_increase_allowance) : (
                    (
                        not $blacklist in (@fun_increase_allowance[i] .. @block_str[#block_str in (0 .. @fun_increase_allowance[i]) + 1])
                        or
                        (#block_str in (0 .. @fun_increase_allowance[i]) == #block_str
                        and not $blacklist in (@fun_increase_allowance[i] .. filesize))
                    )
                )
            )
        )
}