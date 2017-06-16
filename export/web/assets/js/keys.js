var private_prefix = '55';
var key = null;
var my_tx = null;
var paytxfee = 10000;
var nSignedInput = 0;

function select_menu(id) {
    if (id == "tab_unspent")
        $('#tab_unspent').addClass('selected');
    else
        $('#tab_unspent').removeClass('selected');

    if (id == "tab_spent")
        $('#tab_spent').addClass('selected');
    else
        $('#tab_spent').removeClass('selected');

    if (id == "tab_received")
        $('#tab_received').addClass('selected');
    else
        $('#tab_received').removeClass('selected');

}
function pubkey_to_addr(pubkey) {
    rpc_call('pubkeytoaddr', [pubkey], function (data) {
        $('#pubaddr').val(data.result.addr);
    });
}


function privKeyAddr(username,addr,secret) {
    var acName = username.replace('@', '-');
    rpc_call('getprivaddr', [acName, addr], function (keyData) {
        var faddr, paddr, eaddr, crc;
        var DecHexkey   = strtoHexString(un_enc(secret, keyData.result.privkey.slice(0,64)));
        var addr        = private_prefix + DecHexkey+ '01';
       
        h              = sha256(addr);
        h2             = sha256(h);
        crc            = h2.slice(0, 8);
        faddr          = addr + crc;
        paddr          = hex2b(faddr);
        eaddr          = to_b58(paddr);
        $('#privAddr').html(eaddr);
    });
}


function newkey() {
    var addr, sk, hexk;
    addr = $('#privkey').val();
    data = from_b58(addr, ALPHABET);

    crc = toHexString(data.slice(34, 38));
    sk = data.slice(0, 34);
    hexk = toHexString(sk);
    h = sha256(hexk);
    h2 = sha256(h);
    if (crc != h2.slice(0, 8))
        alert('bad key');

    sk = data.slice(1, 33);
    hexk = toHexString(sk);
    key = ec.keyPair({ priv: hexk, privEnc: 'hex' });
    pubkey = key.getPublic().encodeCompressed('hex');
    privkey = hexk;
    pubkey_to_addr(pubkey);
}

function check_key(privKey, pubAddr)
{
    var test_key = ec.keyPair({ priv: privKey, privEnc: 'hex' });
    pubkey = test_key.getPublic().encodeCompressed('hex');
    rpc_call('pubkeytoaddr', [pubkey], function (data) {
        if (data.result.addr != pubAddr) {
            $('#dostake_' + pubAddr).prop('checked', false);
            $('#secret_' + pubAddr).css('color', 'red');
        }
        else
        {
            $('#dostake_' + pubAddr).prop('checked', true);
            $('#secret_' + pubAddr).css  ('color', 'green');
        }
            

    });
}

function rc4_cypher(key, str) {
    var s = [], j = 0, x, res = '';
    for (var i = 0; i < 256; i++) {
        s[i] = i;
    }
    for (i = 0; i < 256; i++) {
        j = (j + s[i] + key.charCodeAt(i % key.length)) % 256;
        x = s[i];
        s[i] = s[j];
        s[j] = x;
    }
    i = 0;
    j = 0;
    for (var y = 0; y < str.length; y++) {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        x = s[i];
        s[i] = s[j];
        s[j] = x;
        res += String.fromCharCode(str.charCodeAt(y) ^ s[(s[i] + s[j]) % 256]);
    }
    return res;
}
function rc4_cypher_arr(key, arr) {
    var s = [], j = 0, x, res = '';
    for (var i = 0; i < 256; i++) {
        s[i] = i;
    }
    for (i = 0; i < 256; i++) {
        j = (j + s[i] + key.charCodeAt(i % key.length)) % 256;
        x = s[i];
        s[i] = s[j];
        s[j] = x;
    }
    i = 0;
    j = 0;
    for (var y = 0; y < arr.length; y++) {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        x = s[i];
        s[i] = s[j];
        s[j] = x;
        res += String.fromCharCode(arr[y] ^ s[(s[i] + s[j]) % 256]);
    }
    return res;
}




function un_enc(secret, HexKey)
{
    var strKey;
    strKey = hex2a(HexKey);
    return rc4_cypher(secret, strKey);
}


function check_ecdsa() {
    // Generate keys
    var key = ec.genKeyPair();

    // Sign message (must be an array, or it'll be treated as a hex sequence)
    var msg = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    var signature = key.sign(msg);
    // Export DER encoded signature in Array
    var derSign = signature.toDER();

    // Verify signature
    console.log(key.verify(msg, derSign));
}
function generateKeys() {
    var ec = new EC('secp256k1');
    // Generate keys
    key = ec.genKeyPair();
    $('#privkey').val(key.getPrivate('hex'));

    pubkey = key.getPublic().encodeCompressed('hex');
    privkey = key.getPrivate('hex');
    pubkey_to_addr(pubkey);
}
function sign_hash(username,addr,secret,sign_data) {

    var acName = username.replace('@', '-');

    $('#bounty_submit').attr('disabled', 'disabled');

    if (sign_data.length == 0) {
        $('#bounty_sig_msg').html('<p style="color:red;">empty twid id</p>');
        return false;
    }
    if (secret.length < 6) {
        $('#bounty_sig_msg').html('<p style="color:red;">secret too short</p>');
        return false;
    }

    rpc_call('getprivaddr', [acName, addr], function (keyData) {

        var DecHexkey = strtoHexString(un_enc(secret, keyData.result.privkey.slice(0,64)));
        var pubkey;

        key     = ec.keyPair({ priv: DecHexkey, privEnc: 'hex' });
        pubkey  = key.getPublic().encodeCompressed('hex');
        rpc_call('pubkeytoaddr', [pubkey], function (data) {

            if (data.result.addr == $('#bounty_addr').val()) {
                var signature = key.sign(sign_data);
                // Export DER encoded signature in Array
                var derSign = signature.toDER('hex');

                $('#bounty_secret').val ('');

                $('#bounty_pubkey').val (pubkey);
                $('#bounty_key').html   (DecHexkey);
                $('#bounty_sig').val    (derSign);
                $('#bounty_sig_msg').html('<p style="color:green;">address check ok</p>');

                $('#bounty_submit').removeAttr('disabled');
            }
            else
            {
                $('#bounty_pubkey').val('');
                $('#bounty_key').val('');
                $('#bounty_sig').val('');
                $('#bounty_sig_msg').html('<p style="color:red;">address check err</p>');
            }

        });

        
    });

}

function import_keys(username, label,table_name) {

    var         arrKey;
    var         encKey;
    var         secret;
    var         acName;
    var         hexKey,HexKey;
    
    if (key == null)
    {
        $('#imp_key_msg').empty();
        $('#prv_key_msg').html('enter a private key');
        return false;
    }
    secret = $('#imp_key').val();
    if (secret.length < 6)
    {
        $('#imp_key_msg').html('key too short (min 6 cars)');
        $('#prv_key_msg').empty();
        return false;
    }
    
    acName = username.replace('@', '-');
    arrKey = key.getPrivate().toArray('be', 32);
    encKey = rc4_cypher_arr(secret, arrKey);
    HexKey = strtoHexString(encKey);

    rpc_call('importkeypair', [acName, label, pubkey, HexKey, 0], function (data) {

        if (data.result.new == 1)
            set_account_pw(acName, $('#pw').val());

        $('#prv_key_msg').empty();
        $('#imp_key_msg').empty();
        get_accounts(table_name , 1);
        get_addrs(username, table_name);

       

        
    });

    return true;
}

function get_addrs_select(username, select_name) {

    var acName = username.replace('@', '-');

    rpc_call('getpubaddrs', [acName], function (data) {
        if ((typeof data.result.addrs === 'undefined') || (data.result.addrs.length == 0)) {
            my_addrs = null;
        }
        else {
            my_addrs = data.result.addrs;
        }
        update_my_addrs_select(select_name);
    });
}
function get_addrs_divs(username, parent_name) {

    var acName = username.replace('@', '-');

    rpc_call('getpubaddrs', [acName], function (data) {

        $('#newaddr').css('display', 'block');
        if ((typeof data.result.addrs === 'undefined') || (data.result.addrs.length == 0)) {
            my_addrs = null;
        }
        else {
            my_addrs = data.result.addrs;
        }
        update_my_addrs_divs(parent_name);
    });
}

function get_addrs(username,table_name) {

    var acName = username.replace('@', '-');
    $('#uname').html(acName);

    rpc_call('getpubaddrs', [acName], function (data) {

        $('#newaddr').css('display', 'block');
        if ((typeof data.result.addrs === 'undefined') || (data.result.addrs.length == 0)) {
            my_addrs = null;
        }
        else {
            my_addrs = data.result.addrs;
        }
        update_my_addrs(table_name);
    });
}



function find_account(accnt_name)
{
    if (my_accounts == null) return null;

    for(var n=0;n<my_accounts.length;n++)
    {
        if (my_accounts[n].name == accnt_name)
            return my_accounts[n];
    }
    return null;
}
function get_accounts(table_name, new_account) {

    rpc_call('listaccounts', [0], function (data) {
        $('#newaddr').css('display', 'block');
        
        if ((typeof data.result.accounts == 'undefined') || (data.result.accounts.length == 0)) {
            my_accounts = null;
        }
        else {
            my_accounts = data.result.accounts;
            update_accounts(new_account);
        }
    });
}





/*
function update_addr_txs() {
    if (addr_txs == null) return;

    var total;
    var thead;
    var num_txs = addr_txs.length;

    thead = document.getElementById("addr_list").tHead;
    thead.rows[0].cells[2].innerHTML = 'category';

    old_tbody = document.getElementById("addr_list").tBodies[0];
    new_tbody = document.createElement('tbody');

    total = 0;
    for (n = 0; n < num_txs; n++) {
        var row = new_tbody.insertRow(n);
        cell = row.insertCell(0);
        cell.className = "time";
        cell.innerHTML = timeConverter(addr_txs[n].time);

        cell = row.insertCell(1);
        cell.className = "recv_tx";
        cell.innerHTML = addr_txs[n].txid;

        cell = row.insertCell(2);
        cell.className = "recv_tx";
        cell.innerHTML = addr_txs[n].category;

        cell = row.insertCell(3);

        if (addr_txs[n].category == "send") {
            cell.className = "addr_send";
            cell.innerHTML = "-" + addr_txs[n].amount / unit;
            total -= addr_txs[n].amount;
        }
        else {
            cell.className = "addr_recv";
            cell.innerHTML = "+" + addr_txs[n].amount / unit;
            total += addr_txs[n].amount;
        }

        cell = row.insertCell(4);
        cell.className = "confirmations";
        cell.innerHTML = '';


    }
    $('#txtotal').html(total / unit);
    old_tbody.parentNode.replaceChild(new_tbody, old_tbody);
}
*/
function list_unspent(address,tbl_name) {
    var old_tbody = document.getElementById(tbl_name).tBodies[0];
    var new_tbody = document.createElement('tbody');
    var addrs;

    if ((typeof address == 'array') || (typeof address == 'object'))
        addrs = address;
    else
        addrs = [address];

    old_tbody.parentNode.replaceChild(new_tbody, old_tbody);


    rpc_call('listunspent', [0, 9999999, addrs], function (data) {
        unspents = data.result.unspents;
        unspents.sort(function (a, b) { return (b.time - a.time); });
        update_unspent(tbl_name);
        addr_tx_total = data.result.total;
  
        $('#unspentaddr').html  (address);
        $('#txtotal').html(addr_tx_total / unit);
        $('#ntx').html(unspents.length);
        $('#total_tx').html(data.result.ntx);
        select_menu("tab_unspent");
    
    });
}

function txinputsigned(txsign)
{
    nSignedInput++;
    if (nSignedInput >= my_tx.txsin.length)
    {
        var txid = txsign.result.txid;
        rpc_call('submittx', [txid], function (){});
        $('#newtxid').html(txid);
        nSignedInput = -1;
    }

}

function signtxinputs(txh,inputs)
{
    nSignedInput = 0;
    for (var n = 0; n < inputs.length; n++) {
        var DecHexkey = $('#dostake_' + inputs[n].srcaddr).attr('privkey');
        var pubKey    = $('#dostake_' + inputs[n].srcaddr).attr('pubkey');
        var mykey     = ec.keyPair({ priv: DecHexkey, privEnc: 'hex' });
        var signature = mykey.sign(inputs[n].signHash, 'hex');
        // Export DER encoded signature in Array
        //var derSign = signature.toDER('hex');
        var derSign   = signature.toLowS();
        rpc_call('signtxinput', [txh, inputs[n].index, derSign, pubKey], txinputsigned);
    }
}

function maketxfrom(address,amount,dstAddr, tbl_name) {
    var addrs;

    if ((typeof address == 'array') || (typeof address == 'object'))
        addrs = address;
    else
        addrs = [address];

   rpc_call('maketxfrom', [addrs, amount, dstAddr], function (data) {
        my_tx = data.result.transaction;
        $('#total_tx').html(data.result.total);
        $('#newtx').html(get_tmp_tx_html(my_tx));
    });
}


function list_spent(address) {
    var old_tbody = document.getElementById("addr_list").tBodies[0];
    var new_tbody = document.createElement('tbody');
    old_tbody.parentNode.replaceChild(new_tbody, old_tbody);


    rpc_call('listspent', [0, 9999999, [address]], function (data) {
        spents = data.result.spents;
        spents.sort(function (a, b) { return (b.time - a.time); });
        update_spent();

        addr_tx_total = data.result.total;

        $('#unspentaddr').html(address);
        $('#txtotal').html(addr_tx_total / unit);
        $('#ntx').html(spents.length);
        $('#total_tx').html(data.result.ntx);
        select_menu("tab_spent");
    });
}

function list_recvs(address) {
    var old_tbody = document.getElementById("addr_list").tBodies[0];
    var new_tbody = document.createElement('tbody');
    old_tbody.parentNode.replaceChild(new_tbody, old_tbody);

    rpc_call('listreceived', [0, 9999999, [address]], function (data) {
        recvs = data.result.received;
        recvs.sort(function (a, b) { return (b.time - a.time); });

        update_recvs();

        addr_tx_total = data.result.total;
        $('#unspentaddr').html(address);
        $('#txtotal').html(addr_tx_total / unit);
        $('#ntx').html(recvs.length);
        $('#total_tx').html(data.result.ntx);


        select_menu("tab_received");
    });
}



function list_staking(addresses) {
    rpc_call('liststaking', [0, 9999999, addresses], function (data) {
        var n;
        stake_unspents = data.result.unspents;
        block_target = data.result.block_target;
        now = data.result.now;
        last_block_time = last_block_time;

        update_staking();

        if (stake_unspents.length > 0)
            staketimer = setTimeout(check_all_staking, 10000);
        else
            clearTimeout(staketimer);
    });
}

function list_staking_unspent(addresses) {
    rpc_call('listunspent', [0, 9999999, addresses], function (data) {
        unspents = data.result.unspents;
        unspents.sort(function (a, b) { return (b.time - a.time); });
        update_unspent('list_table');
    });
}

function scan_addr(address)
{
    rpc_call('rescanaddrs', [[address]], function (data)
    { 
        rpc_call('getpubaddrs', [accountName], function (data) {
            var arAddr = [], stakeAddrAr = [];
            var n;
            my_addrs = data.result.addrs;

            for (n = 0; n < my_addrs.length; n++) {
                if ($('#dostake_' + my_addrs[n].address).is(':checked'))
                    stakeAddrAr[n] = my_addrs[n].address;

                arAddr[n] = my_addrs[n].address;
            }
            list_staking_unspent    (arAddr);
            list_staking            (stakeAddrAr)
            update_unspent          ('list_table');
            update_staking_addrs    ('address_list_table');

        });
    
    });
    
}


function getMyAddrs()
{
    var AddrAr = [];
    for (n = 0; n < my_addrs.length; n++)
    {
        if ($('#dostake_' + my_addrs[n].address).is(':checked'))
            AddrAr.push(my_addrs[n].address);
    }

    return AddrAr;
}