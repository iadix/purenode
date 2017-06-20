/* Write here your custom javascript codes */

var blocks = null;
var block = null;
var blk_page_idx = 0;
var tx_page_idx = 0;
var api_base_url = '';
var site_base_url = '';
var txs = null;
var addrstxs = null;
var selectedhash = null;
var currentAddr = null;

var accountName = null;
var my_accounts = null;
var my_addrs = null;
var sessionid = null;
var addr_txs;
var addr_tx_page_idx = 0;
var addr_tx_total = 0;
var cgi_base = '/api/'
var rpc_base = '/jsonrpc'
var mods = null;
var handlers = null;

var modules_definitions = {};

function rpc_call(in_method, in_params, in_success) {
    $.ajax({
        url: api_base_url + rpc_base,
        data: JSON.stringify({ jsonrpc: '2.0', method: in_method, params: in_params, id: 1 }),  // id is needed !!
        contentType: "application/json; charset=utf-8",
        type: "POST",
        dataType: "json",
        success: in_success,
        error: function (err) { /*alert("Error");*/ }
    });
}

function api_call(in_method, in_params, in_success) {
    $.ajax({
        url: api_base_url + cgi_base + in_method + in_params,
        type: "GET",
        dataType: "json",
        success: in_success,
        error: function (err) { /*alert("Error");*/ }
    });
}

function reverse(s) {
    var o = '';
    for (var i = s.length - 2; i >= 0; i -= 2) {
        o += s[i];
        o += s[i + 1];
    }
    return o;
}


var hexChar = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F"];
function hex32(val) {
    val &= 0xFFFFFFFF;
    var hex = val.toString(16).toUpperCase();
    return reverse(("00000000" + hex).slice(-8));
}

function sha256(s) {                      // Requires jsSHA
    var shaObj = new jsSHA("SHA-256", "HEX");
    shaObj.update(s);
    return shaObj.getHash("HEX");
}
function toHexString(arr) {
    var str = '';
    for (var i = 0; i < arr.length ; i++) {
        str += ((arr[i] < 16) ? "0" : "") + arr[i].toString(16);
    }
    return str;
}

function hex2a(hexx) {
    var hex = hexx.toString();//force conversion
    var str = '';
    for (var i = 0; i < hex.length; i += 2)
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    return str;
}
function hex2b(hexx) {
    var hex = hexx.toString();//force conversion
    var arr = [];
    for (var i = 0; i < hex.length; i += 2)
        arr.push(parseInt(hex.substr(i, 2), 16));
    return arr;
}

function strtoHexString(istr) {
    var str = '';
    for (var i = 0; i < istr.length ; i++) {
        str += ((istr.charCodeAt(i) < 16) ? "0" : "") + istr.charCodeAt(i).toString(16);
    }
    return str;
}


function compare_hash(h1, h2) {
    //console.log('hashes :' + h1 + ' ' + h2);
    for (bn = h1.length - 2; bn >= 0; bn -= 2) {
        b1 = parseInt(h1.slice(bn, bn + 2), 16);
        b2 = parseInt(h2.slice(bn, bn + 2), 16);
        //console.log('hex :' + b1 + ' ' + b2);
        if (b1 < b2)
            return 1;
        else
            return 0;
    }
}


b64s = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"'
function textToBase64(t) {
    var r = ''; var m = 0; var a = 0; var tl = t.length - 1; var c
    for (n = 0; n <= tl; n++) {
        c = t.charCodeAt(n)
        r += b64s.charAt((c << m | a) & 63)
        a = c >> (6 - m)
        m += 2
        if (m == 6 || n == tl) {
            r += b64s.charAt(a)
            if ((n % 45) == 44) { r += "\n" }
            m = 0
            a = 0
        }
    }
    return r
}

function base64ToText(t) {
    var r = ''; var m = 0; var a = 0; var c
    for (n = 0; n < t.length; n++) {
        c = b64s.indexOf(t.charAt(n))
        if (c >= 0) {
            if (m) {
                r += String.fromCharCode((c << (8 - m)) & 255 | a)
            }
            a = c >> m
            m += 2
            if (m == 8) { m = 0 }
        }
    }
    return r
}

var ALPHABET, ALPHABET_MAP, i;
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
ALPHABET_MAP = {};

i = 0;
while (i < ALPHABET.length) {
    ALPHABET_MAP[ALPHABET.charAt(i)] = i;
    i++;
}

function to_b58(buffer) {
    var carry, digits, j;
    if (buffer.length === 0) {
        return "";
    }
    i = void 0;
    j = void 0;
    digits = [0];
    i = 0;
    while (i < buffer.length) {
        j = 0;
        while (j < digits.length) {
            digits[j] <<= 8;
            j++;
        }
        digits[0] += buffer[i];
        carry = 0;
        j = 0;
        while (j < digits.length) {
            digits[j] += carry;
            carry = (digits[j] / 58) | 0;
            digits[j] %= 58;
            ++j;
        }
        while (carry) {
            digits.push(carry % 58);
            carry = (carry / 58) | 0;
        }
        i++;
    }
    i = 0;
    while (buffer[i] === 0 && i < buffer.length - 1) {
        digits.push(0);
        i++;
    }
    return digits.reverse().map(function (digit) {
        return ALPHABET[digit];
    }).join("");
};



function from_b58(S,           //Base58 encoded string input
    A             //Base58 characters (i.e. "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
) {
    var d = [],   //the array for storing the stream of decoded bytes
        b = [],   //the result byte array that will be returned
        i,        //the iterator variable for the base58 string
        j,        //the iterator variable for the byte array (d)
        c,        //the carry amount variable that is used to overflow from the current byte to the next byte
        n;        //a temporary placeholder variable for the current byte
    for (i in S) { //loop through each base58 character in the input string
        j = 0,                             //reset the byte iterator
        c = A.indexOf(S[i]);             //set the initial carry amount equal to the current base58 digit
        if (c < 0)                          //see if the base58 digit lookup is invalid (-1)
            return undefined;              //if invalid base58 digit, bail out and return undefined
        c || b.length ^ i ? i : b.push(0); //prepend the result array with a zero if the base58 digit is zero and non-zero characters haven't been seen yet (to ensure correct decode length)
        while (j in d || c) {               //start looping through the bytes until there are no more bytes and no carry amount
            n = d[j];                      //set the placeholder for the current byte
            n = n ? n * 58 + c : c;        //shift the current byte 58 units and add the carry amount (or just add the carry amount if this is a new byte)
            c = n >> 8;                    //find the new carry amount (1-byte shift of current byte value)
            d[j] = n % 256;                //reset the current byte to the remainder (the carry amount will pass on the overflow)
            j++                            //iterate to the next byte
        }
    }
    while (j--)               //since the byte array is backwards, loop through it in reverse order
        b.push(d[j]);      //append each byte to the result
    return new Uint8Array(b) //return the final byte array in Uint8Array format
}


function make_mime_table(div_name, mimes) {
    var html = '<table class="table" >';
    html += '<thead><tr><th>extension</th><th>mime</th></tr></thead>';
    html += '<tbody>';
    for (var mimek in mimes) {
        html += '<tr><td>' + mimek + '</td><td>' + mimes[mimek] + '</td></tr>';
    }
    html += '</tbody>';
    html += '</table>';
    $('#' + div_name).html(html);
}


function twit_id_from_url(url_html_id) {
    var urlsegs, username, funcseg;
    var urlinput = document.getElementById(url_html_id);
    var twit_url = urlinput.value;
    var parser = document.createElement('a');

    parser.href = twit_url;

    urlsegs = parser.pathname.split('/');
    username = urlsegs[1];
    funcseg = urlsegs[2];
    twit_id = urlsegs[3];

    if ((parser.hostname.toLowerCase() != "twitter.com")) {
        return false;
    }
    if ((funcseg.toLowerCase() != "status")) {
        return false;
    }
    $('#tweet_id').val(twit_id);
    $('#tweet_user').val(username);
}


function check_sig(msg, sig, key, parent) {
    if (ec.verify(msg, sig, key, 'hex'))
        $('#' + parent).addClass('checked');
    else
        $('#' + parent).addClass('invalid');
}

function check_hash(twit_id, parent) {
    var bhash = $('#th_' + twit_id).html();
    var bounty = {};

    bounty['tweet_id'] = $('#tid_' + twit_id).html();
    bounty['time'] = $('#time_' + twit_id).attr('time');
    bounty['prevhash'] = $('#ph_' + twit_id).html();
    bounty['user_dir'] = $('#tu_' + twit_id).html();
    bounty['pubkey'] = $('#tpk_' + twit_id).val();
    bounty['signature'] = $('#tsig_' + twit_id).val();
    bounty['reward'] = $('#tr_' + twit_id).html();
    bounty['adm_pubkey'] = $('#tapk_' + twit_id).val();

    var hash_data = bounty['tweet_id'] + bounty['reward'] + bounty['prevhash'] + bounty['time'] + bounty['user_dir'] + bounty['pubkey'] + bounty['signature'] + bounty['adm_pubkey'];
    var hexDat = strtoHexString(hash_data.toString());
    var hash1 = sha256(hexDat);
    var hash2 = sha256(hash1);
    if (hash2 == bhash)
        $('#' + parent + twit_id).addClass('checked');
    else
        $('#' + parent + twit_id).addClass('invalid');

}



function make_scripts_html(name, script_list)
{
    $('#' + name).empty();
    scripts = script_list;
    for (var i = 0; i < scripts.length; i++) {
        var html = '';
        html  = '<div>'
        html += '<section>'
        html += '<h1><strong>' + scripts[i].file + '</strong></h1>';
        for (var scriptk in scripts[i]) {
            var script_var = scripts[i][scriptk];
            html += '<div>';
            html += '<label  ><h3 onclick=" $(\'#var_' + scriptk + '\').slideToggle();">' + scriptk + '</h3></label>';
            if ((typeof script_var=='object')||(typeof script_var=='Array')||(script_var.length < 32))
            {
                if (typeof script_var=='object')
                {
                    for(var ne=0;ne<script_var.length;ne++)
                    {
                        html += '<div>' + script_var[ne] + '</div>';
                    }
                }
                else
                    html += '&nbsp;:&nbsp;<span>' + script_var + '</span>';
            }
                
            else {
                var str='';

                if (typeof script_var == 'string')
                    str = script_var.replace(/(?:\r\n|\r|\n)/g, '<br />');
                else if (typeof script_var == 'integer')
                    str = script_var.toString();

                html += '<div id="var_'+scriptk+'" class="script_proc">' + str + '</div>';
            }
            html += '</div>'
        }
        html += '</section>';
        html += '</div>'
        $('#' + name).append(html);
    }
}


function make_handlers_html(name, handlers_list) {
    $('#' + name).empty();
    handlers = handlers_list;
    var html = '';
     html = '<div>'
     html += '<section>'
      for (var handlerk in handlers) {
          var script_var = handlers[handlerk];
            var str = script_var.replace(/(?:\r\n|\r|\n)/g, '<br />');
            html += '<div>';
            html += '<label  ><h3 onclick=" $(\'#msg_' + handlerk + '\').slideToggle();">' + handlerk + '(node,payload)</h3></label>';
            html += '<div id="msg_' + handlerk + '" class="script_proc">' + str + '</div>';
            html += '</div>'
        }
        html += '</section>';
        html += '</div>'
        $('#' + name).append(html);
    
}

function find_proc_name(def,proc_name)
{
    if (typeof def.methods != 'undefined') {
        for (var n = 0; n < def.methods.length; n++) {
            if (def.methods[n].name == proc_name) {
                return def.methods[n];
            }
        }
    }
    return null;
}

//var protocol_def = { "name": "protocol_adx", "file": "modz/protocol_adx", "desc": "parsing and manipulation of network packet according to protocol definition.", "methods": [{ "name": "add_bitcore_addr", "desc": "add a bitcore address object as child of the node", "params": [{ "name": "node", "type": "zone ref", "desc": "parent object" }, { "name": "ip address", "type": "ip", "desc": "ip of the node" }, { "name": "port", "type": "int", "desc": "port of the node" }, { "name": "services", "type": "int", "desc": "services of the node" }] }, { "name": "compute_payload_size", "desc": "compute serialized size of the payload object in bytes", "params": [{ "name": "payload", "type": "zone ref", "desc": "object to serialize" }] }, { "name": "create_block_message", "desc": "create a block message object", "params": [{ "name": "node", "type": "zone ref", "desc": "target node" }, { "name": "header", "type": "zone ref", "desc": "header of the block" }, { "name": "tx_list", "type": "zone ref", "desc": "transactions of the block" }, { "name": "signature", "type": "string", "desc": "block signature" }, { "name": "block_pack", "type": "zone ref", "desc": "out packet" }] }, { "name": "create_getaddr_message" }, { "name": "create_getdata_message" }, { "name": "create_getheaders_message" }, { "name": "create_inv_message" }, { "name": "create_ping_message" }, { "name": "create_pong_message" }, { "name": "create_getblocks_message" }, { "name": "create_getdata_message" }, { "name": "create_verack_message" }, { "name": "create_version_message" }, { "name": "get_node_size" }, { "name": "get_version" }, { "name": "init_node" }, { "name": "init_protocol" }, { "name": "new_message" }, { "name": "read_node" }, { "name": "serialize_children" }, { "name": "serialize_message" }, { "name": "unserialize_message" }, { "name": "write_node" }] };
function fill_module_def_html(def) {

    modules_definitions[def.name] = def;

    $('#mod_infos_' + def.name).prepend('<h3>'+def.desc+'</h3>');
    $('#mod_procs_' + def.name + ' li').each(function (index)
    {
        var proc = find_proc_name(def,$(this).attr('method'));
        if (proc != null) {

            $(this).find('.desc').html(proc.desc);
            var args = '(';
            if (typeof proc.params != 'undefined') {
                var first = 1;
                for (var i = 0; i < proc.params.length; i++) {
                    if (!first)
                        args += ',&nbsp;';

                    args += proc.params[i].name;
                    args += '<span style="font-size:8px;">' + proc.params[i].desc + '</span>';
                    first = 0;
                }
            }
            args += ')';
            $(this).find('.args').html(args);
        }
    })
    

}
function make_modules_html(name, modules) {
    $('#' + name).empty();
    for (var i = 0; i < modules.length; i++) {
        var html = '';

        if (typeof modules[i].module != 'undefined')
            var mDef = modules[i].module;
        else
            var mDef = modules[i];

        html  = '<section>'
        html += '<h1 onclick="$(\'#mod_infos_' + mDef.name + '\').toggle();" >';
        html += '<img src="/assets/img/mod.gif" alt="module" />';
        html += '<strong>' + mDef.name + '</strong>';
        if (typeof modules[i].base != 'undefined')html += '&nbsp;' + modules[i].base;
        html += '</h1>';

        html += '<div style="display:none;" id="mod_infos_' + mDef.name+'" >';
        html += '<div><span>file :</span><span>' + mDef.file + '</span></div>';
        html += '<div><span>size :</span><span>' + mDef.size + '</span>&nbsp;bytes</div>';

        html += '<h4>methods</h4>';

        html += '<ul id="mod_procs_' + mDef.name + '" style="padding-left:12px; list-style: square inside url(/assets/img/proc.gif);"  ;>'
        for (var n = 0; n < mDef.exports.length; n++) {
            html += '<li  method="' + mDef.exports[n] + '">'
            if (modules[i].type == 'cgi')
                html += '<a onclick="click_cgi_method(mods[' + i + '],\'' + mDef.exports[n] + '\'); return false;" href="' + modules[i].base + mDef.exports[n] + '" >' + mDef.exports[n] + '</a>';
            else if (modules[i].type == 'rpc')
                html += '<a onclick="click_rpc_method(mods[' + i + '],\'' + mDef.exports[n] + '\'); " href="#api_div" >' + mDef.exports[n] + '</a>';
            else 
                html += '<a >' + mDef.exports[n] + '</a>';

            html += '<span  class="args"></span>';
            html += '<p  class="desc"></p>';

            
            html += '</li>';
        }
        html += '</ul>'

        html += '</div>'
        html += '</section>';
        $('#' + name).append(html);
    }
}


function make_var_html(label,val)
{
    return '<div class="row"><div class="col-md-2"><label>'+label+'</label></div><div class="col-md-2"><span >'+val+'</span></div></div>';
}

function make_node_html(name,node)
{
    $('#'+name).append('<h2>'+node.user_agent+'</h2>');
    $('#' + name).append(make_var_html("address", node.p2p_addr.addr));
    $('#' + name).append(make_var_html("port", node.p2p_addr.port));
    $('#' + name).append(make_var_html("version", node.version));
    $('#'+name).append(make_var_html("height",node.block_height));
    $('#'+name).append('<hr/>');
}

function get_tx_html(tx, n) {
    var new_html = '';
    var vin, vout;

    if (typeof tx.vin != 'undefined')
        vin = tx.vin;
    else if(typeof tx.txsin != 'undefined')
        vin = tx.txsin;

    if (typeof tx.vout != 'undefined')
        vout = tx.vout;
    else if (typeof tx.txsout != 'undefined')
        vout = tx.txsout;

    new_html = '<div class="row justify-content-md-center tx_row fade in" style="border-bottom:1px solid #000;margin-bottom:2px;" onclick="show_tx(\'' + tx.txid + '\');" >';
    new_html += '<div class="col-md-5  align-self-start" >';
    new_html += '<a class="tx_lnk" onclick="SelectTx(\'' + tx.txid + '\'); return false;" href="' + site_base_url + '/tx/' + tx.txid + '">' + '#' + n + '</a>';
    new_html += timeConverter(tx.time);

    if (tx.isNull == true) {
        new_html += '0&nbsp;in&nbsp;';
        new_html += '0&nbsp;out';
    }
    else {
        new_html += vin.length + '&nbsp;in&nbsp;';
        new_html += vout.length + '&nbsp;out';
    }
    new_html += '</div>';
    if (tx.blockheight) {
        new_html += '<div class="col-md-6 align-self-end" >';
        new_html += 'block #' + tx.blockheight;
        new_html += '<span class="block_idate" >' + timeConverter(tx.blocktime) + '</span>';
        new_html += '</div>';
    }
    new_html += '</div>';

    new_html += '<div class="row tx_infos"  style="border-bottom:1px dashed #000;margin-bottom:2px;" id="tx_infos_' + tx.txid + '" >';
    new_html += '<span style="  width: 100%;  display: inline-block;text-align:center" >transaction id :' + tx.txid + '</span><br/>';
    if (tx.isNull == true) {
        new_html += '<div class="col-md-6" >' + '<h2>inputs</h2>' + '#0 null&nbsp;' + '</div>';
        new_html += '<div class="col-md-6" >' + '<h2>outputs</h2>' + '#0 null&nbsp;' + '</div>';
    }
    else {
        new_html += '<div class="col-md-6" >';
        new_html += '<h2>inputs</h2>';
        if ((tx.isCoinBase == true)) {

            if ((vin) && (vin.length > 0))
                new_html += vin[0].coinbase;
        }
        else{
            var nins, nouts;
            nins = vin.length;
            for (nn = 0; nn < nins; nn++) {
                new_html += '<div class="row">';
                new_html += '<div class="col-md-8" >';
                new_html += '#' + nn + '&nbsp;';

                if (vin[nn].addresses) {

                    if (vin[nn].addresses.indexOf(currentAddr) >= 0)sent += vin[nn].value;

                    new_html += '<a href= "' + site_base_url + '/address/' + vin[nn].addresses[0] + '" class="tx_address">' + vin[nn].addresses[0] + '</a>';
                }
                else if (vin[nn].srcaddr) {
                    if (vin[nn].srcaddr==currentAddr)sent += vin[nn].value;
                    new_html += '<a href= "' + site_base_url + '/address/' + vin[nn].srcaddr + '" class="tx_address">' + vin[nn].srcaddr + '</a>';
                }
                new_html += '<span class="tx_amnt" >' + vin[nn].value / unit + '</span>';
                new_html += '</div>';
                new_html += '</div>';
            }
        }
        new_html += '</div>';



        new_html += '<div class="col-md-6" >';
        new_html += '<h2>outputs</h2>';
        if (vout) {
            nouts = vout.length;
            for (nn = 0; nn < nouts; nn++) {

                new_html += '<div class="row">';
                new_html += '<div class="col-md-8" >';

                if (vout[nn].isNull == true)
                    new_html += '#0 null &nbsp;';
                else {
                    new_html += '#' + nn + '&nbsp;';

                    if (vout[nn].addresses) {
                        if (vout[nn].addresses.indexOf(currentAddr) >= 0) recv += vout[nn].value;
                        new_html += '<a href="' + site_base_url + '/address/' + vout[nn].addresses[0] + '" class="tx_address" >' + vout[nn].addresses[0] + '</a>';
                    } else if (vout[nn].dstaddr) {
                        if (vout[nn].dstaddr==currentAddr)recv += vout[nn].value;
                        new_html += '<a href="' + site_base_url + '/address/' + vout[nn].dstaddr + '" class="tx_address" >' + vout[nn].dstaddr + '</a>';
                    }
                    new_html += '<span class="tx_amnt" >' + vout[nn].value / unit + '</span>';
                }
                new_html += '</div>';
                new_html += '</div>';
            }
        }
        new_html += '</div>';
    }
    new_html += '</div>';

    return new_html;
}

function get_tmp_tx_html(tx) {
    var new_html = '';
    var vin, vout;
    var nins, nouts;
    if (typeof tx.vin != 'undefined')
        vin = tx.vin;
    else if (typeof tx.txsin != 'undefined')
        vin = tx.txsin;

    if (typeof tx.vout != 'undefined')
        vout = tx.vout;
    else if (typeof tx.txsout != 'undefined')
        vout = tx.txsout;

    if (tx.isNull == true) {
        new_html += '0&nbsp;in&nbsp;';
        new_html += '0&nbsp;out';
    }
    else {
        new_html += vin.length + '&nbsp;in&nbsp;';
        new_html += vout.length + '&nbsp;out';
    }
    
    new_html += '<div class="row"  style="border-bottom:1px dashed #000;margin-bottom:2px;" >';
    
    new_html += '<div class="col-md-6" >';
    new_html += '<h2>inputs</h2>';

    if (vin) {
        nins = vin.length;
        for (nn = 0; nn < nins; nn++) {
            new_html += '<div class="row">';

            new_html += '<div class="col-md-8" >';
            new_html += '#' + vin[nn].index + '&nbsp;';
            new_html += '<a href= "' + site_base_url + '/address/' + vin[nn].srcaddr + '" class="tx_address">' + vin[nn].srcaddr + '</a>';
            new_html += '<span class="tx_amnt" >' + vin[nn].value / unit + '</span>';
            new_html += '</div>';
            new_html += '</div>';
        }
    }
    new_html += '</div>';
    
    new_html += '<div class="col-md-6" >';
    new_html += '<h2>outputs</h2>';
    if (vout) {
        nouts = vout.length;
        for (nn = 0; nn < nouts; nn++) {
            new_html += '<div class="row">';
            new_html += '<div class="col-md-8" >';
            new_html += '#' + nn + '&nbsp;';
            new_html += '<a href="' + site_base_url + '/address/' + vout[nn].addr + '" class="tx_address" >' + vout[nn].addr + '</a>&nbsp;';
            new_html += '<span class="tx_amnt" >' + vout[nn].value / unit + '</span>';
            new_html += '</div>';
            new_html += '</div>';
        }
    }
    new_html += '</div>';
    new_html += '</div>';

    return new_html;
}

function update_txs(txs, tbl_name) {
    var num_txs = txs.length;
    txs.sort(function (a, b) { return (b.blocktime - a.blocktime); });


    if (document.getElementById(tbl_name).tBodies) {
        var old_tbody = document.getElementById(tbl_name).tBodies[0];
        var new_tbody = document.createElement('tbody');

        for (n = 0; n < num_txs; n++) {
            var row = new_tbody.insertRow(n * 2);
            var cell;
            row.className = "txhdr";

            cell = row.insertCell(0);
            cell.className = "tx_hash";
            cell.innerHTML = '<span class="tx_expand" onclick="show_tx(\'' + txs[n].txid + '\'); if(this.innerHTML==\'+\'){ this.innerHTML=\'-\'; }else{ this.innerHTML=\'+\'; } ">+</span><a class="tx_lnk" onclick="SelectTx(\'' + txs[n].txid + '\'); return false;" href="' + site_base_url + '/tx/' + txs[n].txid + '">' + '#' + n + '</a>&nbsp;' + timeConverter(txs[n].blocktime);

            cell = row.insertCell(1);
            cell.className = "txmine";
            cell.innerHTML = 'block #' + txs[n].blockheight + ' ' + timeConverter(txs[n].blocktime);


            row = new_tbody.insertRow(n * 2 + 1);

            row.id = "tx_infos_" + txs[n].txid;
            row.className = "tx_infos";

            if (txs[n].isNull == true) {
                cell = row.insertCell(0);
                cell.className = "txins";
                cell.innerHTML = '#0 null <br/>';
                cell = row.insertCell(1);
                cell.className = "txouts";
                cell.innerHTML = '#0 null <br/>';
            }
            else {
                cell = row.insertCell(0);
                cell.className = "txins";
                if (txs[n].isCoinBase == false) {
                    var nins, nouts;
                    var html = '';

                    nins = txs[n].vin.length;
                    for (nn = 0; nn < nins; nn++) {
                        var hh;
                        if (tbl_name == 'tx_list')
                            hh = ' <a href= "' + site_base_url + '/address/' + txs[n].vin[nn].addresses[0] + '" class="tx_address">' + txs[n].vin[nn].addresses[0] + '</a>';
                        else if (txs[n].vin[nn].addresses)
                            hh = txs[n].vin[nn].addresses[0];

                        html += '#' + txs[n].vin[nn].n + '&nbsp' + hh + '&nbsp' + txs[n].vin[nn].value / unit + '  <br/>';
                    }
                    cell.innerHTML = html;
                }
                else if ((txs[n].vin) && (txs[n].vin.length > 0)) {
                    cell.innerHTML = 'coin base' + txs[n].vin[0].coinbase;
                }
                cell = row.insertCell(1);
                cell.className = "txouts";

                html = '';
                if (txs[n].vout) {
                    nouts = txs[n].vout.length;
                    for (nn = 0; nn < nouts; nn++) {

                        if (txs[n].vout[nn].isNull == true)
                            html += '#0 null <br/>';
                        else {
                            var hh;

                            if (tbl_name == 'tx_list')
                                hh = ' <a href="' + site_base_url + '/address/' + txs[n].vout[nn].addresses[0] + '" class="tx_address">' + txs[n].vout[nn].addresses[0] + '</span> ';
                            else if (txs[n].vout[nn].addresses)
                                hh = txs[n].vout[nn].addresses[0];

                            html += '#' + txs[n].vout[nn].n + '&nbsp' + hh + '&nbsp' + txs[n].vout[nn].value / unit + ' <br/>';
                        }
                    }
                }

                cell.innerHTML = html;
            }
        }
        old_tbody.parentNode.replaceChild(new_tbody, old_tbody);
    }
    else {
        var new_html = '';
        $('#' + tbl_name).empty();
        for (n = 0; n < num_txs; n++) {
            new_html += get_tx_html(txs[n], n);
        }
        $('#' + tbl_name).html(new_html);
    }
}

function update_mempool_txs(txs, tbl_name) {
    var num_txs = txs.length;
    txs.sort(function (a, b) { return (b.time - a.time); });


    if (document.getElementById(tbl_name).tBodies) {
        var old_tbody = document.getElementById(tbl_name).tBodies[0];
        var new_tbody = document.createElement('tbody');

        for (n = 0; n < num_txs; n++) {
            var row = new_tbody.insertRow(n * 2);
            var cell;
            row.className = "txhdr";

            cell = row.insertCell(0);
            cell.className = "tx_hash";
            cell.innerHTML = '<span class="tx_expand" onclick="show_tx(\'' + txs[n].txid + '\'); if(this.innerHTML==\'+\'){ this.innerHTML=\'-\'; }else{ this.innerHTML=\'+\'; } ">+</span><a class="tx_lnk" onclick="SelectTx(\'' + txs[n].txid + '\'); return false;" href="' + site_base_url + '/tx/' + txs[n].txid + '">' + '#' + n + '</a>&nbsp;' + timeConverter(txs[n].time);

            row = new_tbody.insertRow(n * 2 + 1);

            row.id = "tx_infos_" + txs[n].txid;
            row.className = "tx_infos";
      
           cell = row.insertCell(0);
           cell.className = "txins";
           
            var nins, nouts;
            var html = '';

            nins = txs[n].vin.length;
            for (nn = 0; nn < nins; nn++) {

                var hh = ' <a href= "' + site_base_url + '/address/' + txs[n].vin[nn].dstaddr + '" class="tx_address">' + txs[n].vin[nn].dstaddr + '</a>';

                html += '#' + nn + '&nbsp' + hh + '&nbsp' + txs[n].vin[nn].value / unit + '  <br/>';
            }
            cell.innerHTML = html;
           
           cell = row.insertCell(1);
           cell.className = "txouts";

           html = '';
           if (txs[n].vout) {
               nouts = txs[n].vout.length;
               for (nn = 0; nn < nouts; nn++) {

                   var hh = ' <a href="' + site_base_url + '/address/' + txs[n].vout[nn].dstaddr + '" class="tx_address">' + txs[n].vout[nn].dstaddr + '</span> ';
                    html += '#' + nn + '&nbsp' + hh + '&nbsp' + txs[n].vout[nn].value / unit + ' <br/>';
               }
           }
           cell.innerHTML = html;
        }
        old_tbody.parentNode.replaceChild(new_tbody, old_tbody);
    }
    else {
        var new_html = '';
        $('#' + tbl_name).empty();
        for (n = 0; n < num_txs; n++) {
            new_html += get_tx_html(txs[n], n);
        }
        $('#' + tbl_name).html(new_html);
    }
}



function update_blocks() {
    var nrow;
    var num_blocks;
    if (blocks != null)
        num_blocks = blocks.length;
    else
        num_blocks = 0;


    if (document.getElementById("list_table") == null) return;

    var thead = document.getElementById("list_table").tHead;
    var old_tbody = document.getElementById("list_table").tBodies[0];
    var new_tbody = document.createElement('tbody');

    if (num_blocks == 0) {
        var row = new_tbody.insertRow(nrow);
        var cell;
        cell = row.insertCell(0);
        cell.className = "block_info";
        cell.innerHTML = '#none';

        cell = row.insertCell(1);
        cell.className = "block_info";
        cell.innerHTML = 0;

        cell = row.insertCell(2);
        cell.className = "block_info";
        cell.innerHTML = '';

        cell = row.insertCell(3);

        cell.className = "block_info staked";
        cell.innerHTML = '---';

        cell = row.insertCell(4);
        cell.className = "block_info";
        cell.innerHTML = '0';

        cell = row.insertCell(5);
        cell.className = "block_info";
        cell.innerHTML = '0';
    }
    else {
        nrow = 0;
        for (n = 0; n < num_blocks; n++) {
            if (!blocks[n].height) continue;
            var row = new_tbody.insertRow(nrow);
            row.id = 'block_' + blocks[n].hash;

            cell = row.insertCell(0);
            cell.className = "block_info block_height";
            cell.setAttribute('data-toggle', "modal");
            cell.setAttribute('data-target', "#blockmodal");
            cell.innerHTML = '#' + blocks[n].height;

            cell = row.insertCell(1);
            cell.className = "block_info block_idate";
            cell.innerHTML = timeConverter(blocks[n].time);

            cell = row.insertCell(2);
            cell.className = "block_info";

            if (blocks[n].isCoinbase)
                cell.innerHTML = blocks[n].reward / unit;
            else
                cell.innerHTML = blocks[n].reward / unit;

            cell = row.insertCell(3);

            if (blocks[n].isCoinbase) {
                cell.className = "block_info mined";
                cell.innerHTML = 'mined';
            }
            else {
                cell.className = "block_info staked";
                cell.innerHTML = 'staked';
            }

            cell = row.insertCell(4);
            cell.className = "block_info";


            if (blocks[n].tx)
                cell.innerHTML = blocks[n].tx.length;

            cell = row.insertCell(5);
            cell.className = "block_info";
            cell.innerHTML = blocks[n].size;
            nrow++;
        }
    }
    old_tbody.parentNode.replaceChild(new_tbody, old_tbody);
    $('.block_info').mouseup(function () { var h = $(this).parent().attr('id').slice(6); tx_page_idx = 0; txs = null; selectBlock(h); list_block_txs(h, 0); });
}

function update_tx(tbl_name) {

    $('#size').html(tx.size);
    $('#txtime').html(timeConverter(tx.time));
    $('#blocktime').html(timeConverter(tx.blocktime));
    $('#txblock').html('<a href="' + site_base_url + '/block/' + tx.blockhash + '">' + tx.blockhash + '</a>');

    if (tx.isCoinbase == true) {
        $('#coinbase').html(tx.vin[0].coinbase);
        $('#coinbase').addClass('visible');
        $('#coinbaselbl').addClass('visible');

    }
    else {
        $('#coinbase').removeClass('visible');
        $('#coinbaselbl').removeClass('visible');
    }

    if (document.getElementById(tbl_name).tBodies) {

        var old_tbody = document.getElementById(tbl_name).tBodies[0];
        var new_tbody = document.createElement('tbody');
        var row = new_tbody.insertRow(0);
        var cell;
        if (tx.isNull == true) {
            cell = row.insertCell(0);
            cell.className = "txins";
            cell.innerHTML = '#0 null <br/>';
            cell = row.insertCell(1);
            cell.className = "txouts";
            cell.innerHTML = '#0 null <br/>';
        }
        else {
            cell = row.insertCell(0);
            cell.className = "txins";
            if (tx.isCoinBase == false) {
                var nins, nouts;
                var html = '';

                nins = tx.vin.length;
                for (nn = 0; nn < nins; nn++) {
                    html += '#' + tx.vin[nn].n + '<a class="tx_address" href="' + site_base_url + '/address/' + tx.vin[nn].addresses[0] + '">' + tx.vin[nn].addresses[0] + '</a>' + '</span>' + tx.vin[nn].value / unit + '  <br/>';
                }
                cell.innerHTML = html;
            }
            else {
                cell.innerHTML = 'coin base' + tx.vin[0].coinbase;
            }
            cell = row.insertCell(1);
            cell.className = "txouts";

            html = '';
            nouts = tx.vout.length;
            for (nn = 0; nn < nouts; nn++) {
                if (tx.vout[nn].isNull == true)
                    html += '#0 null <br/>';
                else
                    html += '#' + tx.vout[nn].n + '<a class="tx_address" href="' + site_base_url + '/address/' + tx.vout[nn].addresses[0] + '">' + tx.vout[nn].addresses[0] + '</a>' + '</span> ' + tx.vout[nn].value / unit + ' <br/>';
            }

            cell.innerHTML = html;
        }

        old_tbody.parentNode.replaceChild(new_tbody, old_tbody);
    }
    else {
        var new_html = '';
        $('#' + tbl_name).empty();
        new_html = get_tx_html(tx, 0);
        $('#' + tbl_name).html(new_html);
    }
    $('#txhash').html(tx.txid);

}



function update_addr_txs(tbl_name) {
    var num_txs = txs.length;
    var balance = 0;;

    recv = 0;
    sent = 0;
    if (document.getElementById(tbl_name).tBodies) {

        var old_tbody = document.getElementById(tbl_name).tBodies[0];
        var new_tbody = document.createElement('tbody');

        for (n = 0; n < num_txs; n++) {
            var row = new_tbody.insertRow(n * 2);
            row.className = "txhdr";

            cell = row.insertCell(0);
            cell.className = "tx_hash";
            cell.innerHTML = '<a id="addr_tx_"' + txs[n].txid + '" href="' + site_base_url + '/tx/' + txs[n].txid + '">' + txs[n].txid + '</a>';


            cell = row.insertCell(1);
            cell.className = "txmine";
            cell.innerHTML = 'mined on ' + timeConverter(txs[n].blocktime);

            row = new_tbody.insertRow(n * 2 + 1);



            if (txs[n].isNull == true) {
                cell = row.insertCell(0);
                cell.className = "txins";
                cell.innerHTML = '#0 null <br/>';
                cell = row.insertCell(1);
                cell.className = "txouts";
                cell.innerHTML = '#0 null <br/>';
            }
            else {
                cell = row.insertCell(0);
                cell.className = "txins";
                if (txs[n].isCoinBase == false) {
                    var nins, nouts;
                    var html = '';

                    nins = txs[n].vin.length;
                    for (nn = 0; nn < nins; nn++) {
                        html += '#' + txs[n].vin[nn].n;

                        if (txs[n].vin[nn].addresses) {
                            if (txs[n].vin[nn].addresses.indexOf(currentAddr) >= 0)
                                sent += txs[n].vin[nn].value;

                            html += ' <a href="' + txs[n].vin[nn].addresses[0] + '" class="tx_address">' + txs[n].vin[nn].addresses[0] + '</a> ';
                        }


                        html += txs[n].vin[nn].value / unit + '  <br/>';




                    }
                    cell.innerHTML = html;
                }
                else if ((txs[n].vin) && (txs[n].vin.length > 0)) {
                    cell.innerHTML = 'coin base' + txs[n].vin[0].coinbase;
                }
                cell = row.insertCell(1);
                cell.className = "txouts";

                html = '';

                if (txs[n].vout) {
                    nouts = txs[n].vout.length;
                    for (nn = 0; nn < nouts; nn++) {
                        if (txs[n].vout[nn].isNull == true)
                            html += '#0 null <br/>';
                        else {
                            html += '#' + txs[n].vout[nn].n;

                            if (txs[n].vout[nn].addresses) {
                                if (txs[n].vout[nn].addresses.indexOf(currentAddr) >= 0)
                                    recv += txs[n].vout[nn].value;

                                html += ' <a href="' + txs[n].vout[nn].addresses[0] + '" class="tx_address">' + txs[n].vout[nn].addresses[0] + '</a> ';
                            }
                            html += txs[n].vout[nn].value / unit + ' <br/>';
                        }
                    }
                }
                cell.innerHTML = html;
            }
        }
        old_tbody.parentNode.replaceChild(new_tbody, old_tbody);
    }
    else {
        var new_html = '';
        $('#' + tbl_name).empty();
        for (n = 0; n < num_txs; n++) {
            new_html += get_tx_html(txs[n], n);
        }
        $('#' + tbl_name).html(new_html);
    }


    balance = recv - sent;
    $("#Received").html(recv / unit);
    $("#Sent").html(sent / unit);
    $("#Balance").html(balance / unit);
}

function update_addr_list() {
    if (addrs == null) return;
    var num_addrs = addrs.length;
    var old_tbody = document.getElementById("address_list_table").tBodies[0];
    var new_tbody = document.createElement('tbody');

    for (n = 0; n < num_addrs; n++) {
        var row = new_tbody.insertRow(n);
        var cell;

        cell = row.insertCell(0);
        cell.className = "address";
        cell.innerHTML = addrs[n].addr;

        cell = row.insertCell(1);
        cell.className = "addr_received";
        cell.innerHTML = '<span>' + addrs[n].amount / unit + '</span>';
    }
    old_tbody.parentNode.replaceChild(new_tbody, old_tbody);
    $('.address').click(function () { list_txs($(this).html()); if (scanTimer != null) { clearTimeout(scanTimer); scanTimer = null; } scan_status($(this).html()); });
}

function resetblock(block) {

    $("#height").empty();
    $("#hash").empty();
    $("#previousblockhash").empty();
    $("#nextblockhash").empty();
    $("#merkleroot").empty();
    $("#confirmations").empty();
    $("#difficulty").empty();
    $("#nonce").empty();
    $("#reward").empty();
    $("#size").empty();
    $("#bits").empty();
    $("#diffhash").empty();
    $("#proofhash").empty();
    $("#stakemodifier2").empty();
    $("#time").empty();
    $("#version").empty();
    $("#txs").empty();
    $("#blockhash").empty();
}


function updateblock(block) {
    $("#height").html(block.height);
    $("#hash").html(block.hash);
    $("#previousblockhash").html(block.previousblockhash);
    $("#nextblockhash").html(block.nextblockhash);
    $("#merkleroot").html(block.merkleroot);
    $("#confirmations").html(block.confirmations);
    $("#difficulty").html(block.difficulty);
    $("#nonce").html(block.nonce);
    $("#reward").html(block.reward);
    $("#size").html(block.size);
    $("#bits").html('0x' + block.bits.toString(16));
    $("#diffhash").html(block.hbits);
    $("#proofhash").html(block.proofhash);
    $("#stakemodifier2").html(block.stakemodifier2);
    $("#time").html(timeConverter(block.time));
    $("#version").html(block.version);
    $("#txs").empty();
    if (block.tx) {
        ntx = block.tx.length;
        for (n = 0; n < ntx; n++) {
            $("#txs").append('<div onmouseup="SelectTx(\'' + block.tx[n] + '\');" >' + block.tx[n] + '</div>');
        }
    }
    $("#blockhash").html(block.hash);


}



function update_filter_list() {
    var html = 'filters : <br/>';
    $('#blk_filter_list').empty();
    for (var i = 0; i < blk_filters.length; i++) {
        html += '<div><span onclick="remove_filter(' + i + ');" style="color:red;">X</span>' + blk_filters[i] + '</div>';
    }
    $('#blk_filter_list').html(html);
}




function timeConverter(UNIX_timestamp) {
    var a = new Date(UNIX_timestamp * 1000);
    var months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    var year = a.getFullYear();
    var month = months[a.getMonth()];
    var date = a.getDate();
    var hour = a.getHours();
    var min = a.getMinutes();
    var sec = a.getSeconds();
    var time = '<span class="block_date">'+date + ' ' + month + ' ' + year + '</span><span class="block_time">' + hour + ':' + min + ':' + sec+'</span>';
    return time;
}


function dateConverter(UNIX_timestamp) {
    var a = new Date(UNIX_timestamp * 1000);
    var months = ['01', '02', '03', '04', '05', '06', '07', '08', '09', '10', '11', '12'];
    var year = a.getFullYear();
    var month = months[a.getMonth()];
    var date;

    if (a.getDate() < 10)
        date = '0' + a.getDate();
    else
        date = a.getDate();

    var time = year + '-' + month + '-' + date;
    return time;
}

function show_tx(txid) {
    if ($('#tx_infos_' + txid).css('display') == 'none') {
        $('#tx_infos_' + txid).animate({ display: block, height: "toggle" });
    }
    else {
        $('#tx_infos_' + txid).animate({ display: 'none', height: "toggle" });

    }
}


function update_my_addrs(table_name) {
    var old_tbody = document.getElementById(table_name).tBodies[0];
    var new_tbody = document.createElement('tbody');

    

    if ((my_addrs == null) || (my_addrs.length == 0)) {
        document.getElementById(table_name).style.display = 'none';
        $('#myaddrhdr').html('no addresses');
    }
    else {
        var num_addrs = my_addrs.length;

     
        for (n = 0; n < num_addrs; n++) {
            var row = new_tbody.insertRow(n);
            var cell;
            row.className = "my_wallet_addr";
            row.setAttribute("addr", my_addrs[n].address)

            cell = row.insertCell(0);
            cell.className = "addr_label";
            cell.setAttribute("title", my_addrs[n].address)
            cell.innerHTML = my_addrs[n].label;

            cell = row.insertCell(1);
            cell.className = "balance_confirmed";
            cell.innerHTML = '<span>' + my_addrs[n].amount / unit + '</span>';

            cell = row.insertCell(2);
            cell.className = "balance_unconfirmed";
            cell.innerHTML = '<span>' + my_addrs[n].unconf_amount / unit + '</span>';
        }
        document.getElementById(table_name).style.display = 'block';
        $('#myaddrhdr').html(num_addrs + ' addresses');
    }
    old_tbody.parentNode.replaceChild(new_tbody, old_tbody);

    $('.my_wallet_addr').click(function () { addr_txs = null; addr_tx_page_idx = 0; list_unspent($(this).attr('addr'),$('#'+table_name).attr('txdiv')); });
}
function update_staking() {
    if (stake_unspents == null) return;
    if (stake_unspents.length > 0) {
        $('#do_staking').prop('disabled', false);

        var totalweight = 0;
        for (var n = 0; n < stake_unspents.length; n++) {
            totalweight += stake_unspents[n].weight;
        }
        $('#stakeweight').html(totalweight / unit);
        $('#nstaketxs').html(stake_unspents.length);
        $('#stake_msg').empty();

        staketimer = setTimeout(check_all_staking, 10000);
    }
    else {
        $('#do_staking').prop('disabled', true);
        $('#stakeweight').html('0');
        $('#nstaketxs').html('0');
        $('#stake_msg').html('no suitable unspent found');

        clearTimeout(staketimer);
    }
}

function update_staking_addrs(table_name) {

    var old_tbody = document.getElementById(table_name).tBodies[0];
    var new_tbody = document.createElement('tbody');

    if ((my_addrs == null) || (my_addrs.length == 0)) {
        document.getElementById(table_name).style.display = 'none';
        $('#myaddrhdr').html('no addresses');
    }
    else {
        var num_addrs = my_addrs.length;
        $('#myaddrhdr').html(num_addrs + ' addresses');

        for (var n = 0; n < num_addrs; n++) {
            var row = new_tbody.insertRow(-1);
            var cell1, cell2, cell3, cell4, cell5,cell6;

            cell1 = row.insertCell(-1);
            cell2 = row.insertCell(-1);
            cell3 = row.insertCell(-1);
            cell4 = row.insertCell(-1);
            cell5 = row.insertCell(-1);
            cell6 = row.insertCell(-1);

            cell1.className = "addr_label";
            cell1.setAttribute("title", my_addrs[n].address)
            cell1.setAttribute("addr", my_addrs[n].address)
            cell1.innerHTML = my_addrs[n].label;

            
            cell2.className = "balance_confirmed";
            cell2.innerHTML = '<span>' + my_addrs[n].amount / unit + '</span>';

            cell3.className = "balance_unconfirmed";
            cell3.innerHTML = '<span>' + my_addrs[n].unconf_amount / unit + '</span>';

            cell4.innerHTML = '<div><input type="password" onchange=" $(\'#dostake_' + my_addrs[n].address + '\').prop(\'checked\',false); " id="secret_' + my_addrs[n].address + '" value="" /></div>';

            cell5.className = "dostake";
            cell5.setAttribute("addr", my_addrs[n].address);
            cell5.innerHTML = '<div><input type="checkbox" id="dostake_' + my_addrs[n].address + '" value="" /></div>';

            cell6.className = "scan";
            cell6.innerHTML = '<div><input addr="' + my_addrs[n].address + '" type="button" value="rescan" onclick="scan_addr($(this).attr(\'addr\'))"; value=""  /></div>';
        }
    }
    old_tbody.parentNode.replaceChild(new_tbody, old_tbody);

    $('.addr_label').click(function () { addr_txs = null; addr_tx_page_idx = 0; list_unspent($(this).attr('addr'), $('#' + table_name).attr('txdiv')); });
  
}

function update_addrs(tbl_name) {
    if (addrs == null) return;
    var num_addrs = addrs.length;
    old_tbody = document.getElementById(tbl_name).tBodies[0];
    new_tbody = document.createElement('tbody');

    for (n = 0; n < num_addrs; n++) {
        var row = new_tbody.insertRow(n);
        cell = row.insertCell(0);
        cell.className = "address";
        cell.innerHTML = addrs[n].address;

        cell = row.insertCell(1);
        cell.className = "balance";
        cell.innerHTML = addrs[n].amount / unit;

    }
    old_tbody.parentNode.replaceChild(new_tbody, old_tbody);
}

function update_my_addrs_select(select_name) {

    $('#' + select_name).empty();

    if ((my_addrs == null) || (my_addrs.length == 0))
        return;

    for (var i = 0; i < my_addrs.length; i++) {
        $('<option value="' + my_addrs[i].address + '">' + my_addrs[i].label + '</option>').appendTo('#' + select_name);
    }
}

function update_my_addrs_divs(parent_name) {

    $('#' + parent_name).empty();
    $('<div class="row"><div class="col-md-4">label</div><div class="col-md-4">balance</div><div class="col-md-4">unconfirmed</div></div>').appendTo('#' + parent_name);
    if ((my_addrs == null) || (my_addrs.length == 0))
        return;

    for (var i = 0; i < my_addrs.length; i++) {
        $('<div class="row"><div class="col-md-4 my_wallet_addr" addr="' + my_addrs[i].address + '" >' + my_addrs[i].label + '</div>' + '<div class="col-md-4">' + my_addrs[i].amount / unit + '</div>' + '<div class="col-md-4">' + my_addrs[i].unconf_amount / unit + '</div>' + '</div>').appendTo('#' + parent_name);
    }

    $('.my_wallet_addr').click(function () { addr_txs = null; addr_tx_page_idx = 0; list_unspent($(this).attr('addr'), $('#' + parent_name).attr('txdiv')); });
}

function update_unspent(tbl_name) {
    var total;
    if (unspents == null) return;
    var num_unspents = unspents.length;
    thead = document.getElementById(tbl_name).tHead;
    old_tbody = document.getElementById(tbl_name).tBodies[0];
    new_tbody = document.createElement('tbody');

    total = 0;
    for (n = 0; n < num_unspents; n++) {
        var row = new_tbody.insertRow(n);

        if ($('#dostake_' + unspents[n].dstaddr).is(':checked'))
            row.className = 'tx_ready';
        else
            row.className = 'tx_error';

        cell = row.insertCell(0);
        cell.className = "time";
        cell.innerHTML = timeConverter(unspents[n].time);

        cell = row.insertCell(1);
        cell.className = "unspent_tx";

        naddr = unspents[n].addresses.length;

        addresses = unspents[n].txid + '<br/>';
        addresses += '<div>';
        addresses += '<a onclick="$(\'#src_addr_' + unspents[n].txid + '\').toggle(); return false;">src</a>';
        addresses += '<div id="src_addr_' + unspents[n].txid + '" style="display:none">';
        while (naddr--) {
            addresses += unspents[n].addresses[naddr] + '<br/>';
        }
        addresses += '</div>';
        addresses += '</div>';
        
        cell.innerHTML = addresses;

        cell = row.insertCell(2);
        cell.className = "addr_amount";
        cell.innerHTML = unspents[n].amount / unit;

        cell = row.insertCell(3);
        cell.className = "tx_conf";
        cell.innerHTML = unspents[n].confirmations;

        total += unspents[n].amount;
    }
    $('#txtotal').html(total / unit);
    old_tbody.parentNode.replaceChild(new_tbody, old_tbody);
}
function update_spent() {
    if (spents == null) return;

    var total;
    var thead;
    var num_spents = spents.length;

    thead = document.getElementById("addr_list").tHead;
    thead.rows[0].cells[2].innerHTML = 'to';

    old_tbody = document.getElementById("addr_list").tBodies[0];
    new_tbody = document.createElement('tbody');

    total = 0;
    for (n = 0; n < num_spents; n++) {
        var row = new_tbody.insertRow(n);

        cell = row.insertCell(0);
        cell.className = "time";
        cell.innerHTML = timeConverter(spents[n].time);

        cell = row.insertCell(1);
        cell.className = "spent_tx";
        cell.innerHTML = spents[n].txid;

        cell = row.insertCell(2);
        cell.className = "addr_to";

        naddr = spents[n].addresses.length;
        addresses = '';

        while (naddr--) {
            addresses += spents[n].addresses[naddr] + '<br/>';
        }
        cell.innerHTML = addresses;


        cell = row.insertCell(3);
        cell.className = "addr_amount";
        cell.innerHTML = spents[n].amount / unit;

        cell = row.insertCell(4);
        cell.className = "tx_conf";
        cell.innerHTML = spents[n].confirmations;
        total += spents[n].amount;
    }

    old_tbody.parentNode.replaceChild(new_tbody, old_tbody);
}

function update_recvs() {
    if (recvs == null) return;

    var total;
    var thead;
    var num_recvs = recvs.length;

    thead = document.getElementById("addr_list").tHead;
    thead.rows[0].cells[2].innerHTML = 'from';

    old_tbody = document.getElementById("addr_list").tBodies[0];
    new_tbody = document.createElement('tbody');

    total = 0;
    for (n = 0; n < num_recvs; n++) {
        var row = new_tbody.insertRow(n);
        var naddr;
        var addresses;

        cell = row.insertCell(0);
        cell.className = "time";
        cell.innerHTML = timeConverter(recvs[n].time);

        cell = row.insertCell(1);
        cell.className = "recv_tx";
        cell.innerHTML = recvs[n].txid;

        cell = row.insertCell(2);
        cell.className = "addr_from";

        naddr = recvs[n].addresses.length;
        addresses = '';

        while (naddr--) {
            addresses += recvs[n].addresses[naddr] + '<br/>';
        }
        cell.innerHTML = addresses;

        cell = row.insertCell(3);
        cell.className = "addr_amount";
        cell.innerHTML = recvs[n].amount / unit;

        cell = row.insertCell(4);
        cell.className = "tx_conf";
        cell.innerHTML = recvs[n].confirmations;


        total += recvs[n].amount;
    }
    old_tbody.parentNode.replaceChild(new_tbody, old_tbody);
}

function get_node_lag(node)
{
    var height = 0;
    for (n = 0; n < node.peer_nodes.length; n++)
    {
        height = Math.max(height, node.peer_nodes[n].block_height+1);
    }
    var now = Math.floor(new Date().getTime() / 1000);
    var diff =  now - node.last_block_time;
    var msec = diff;
    var dd = Math.floor(msec / (60 * 60 * 24));
    msec -= dd * 60 * 60 * 24;
    var hh = Math.floor(msec  / (60 * 60));

    $('#node_time_lag').html(dd+' days, '+hh + 'hours');

    if (node.block_height <= height)
        $('#node_block_lag').html(height-node.block_height + '&nbsp; blocks behind');
    else
        $('#node_block_lag').html(node.block_height - height + '&nbsp; blocks ahead');



}
function deleteAllCookies() {
    var cookies = document.cookie.split(";");

    for (var i = 0; i < cookies.length; i++) {
        var cookie = cookies[i];
        var eqPos = cookie.indexOf("=");
        var name = eqPos > -1 ? cookie.substr(0, eqPos) : cookie;
        document.cookie = name + "=;expires=Thu, 01 Jan 1970 00:00:00 GMT";
    }
}
function get_session(account, pw) {

    deleteAllCookies();
    $.getJSON('/siteapi/getsession/' + account + '/' + pw).done(function (data) { $.cookie("sessionid", data.sessionid); location.reload(); }).error(function (data) { $('#pw').css('border-color', '#F00'); });
}

function clear_session() {
    deleteAllCookies();
    if (sessionid == null) return;
    $.getJSON('/siteapi/clearsession/' + sessionid).done(function (data) { sessionid = null;location.reload(); });
}

function set_account_pw(account,pw) {
    rpc_call('setaccountpw', [account, pw], function (data) { if (data.error == 0) $('#pw').css('border-color', '#0F0'); else $('#pw').css('border-color', '#F00'); });
}


function select_account(account_name)
{
    var acnt=null;

    if (my_accounts == null) return;

    for (var n = 0; n < my_accounts.length; n++)
    {
        if(my_accounts[n].name==account_name)
        {
            acnt = my_accounts[n];
           break;
        }
    }
    if (acnt == null) return;
        
   
    if (acnt.pw) {

        if((logged)&&(accountName == account_name))
        {
            $('#pw').css('display', 'none');
            $('#signin').val('logout');
            $('#signin').click(clear_session);
        }
        else
        {
            $('#pw').css('display', 'inline');
            if (has_site_api) {
                $('#signin').val('login');
                $('#signin').click(function () { get_session(account_name, $('#pw').val()); });
            }
            else
                $('#signin').css('display', 'none');
        }
        
    }
    else {
        $('#signin').val('set pass');
        $('#pw').css('display', 'inline');
        $('#signin').click(function () { set_account_pw(account_name, $('#pw').val()); });
    }
    $('#signin').css('display', 'inline');
    $('#account_name').prop('disabled', true);
    $('#account_name').val(account_name);
    $('#uname').html(accountName);
}



function update_accounts(new_account)
{
    $('#my_account').empty();

    if (new_account!=null)
        $('<option value="">'+new_account+'</option>').appendTo('#my_account');

    for (var i = 0; i < my_accounts.length; i++) {
        var selected;

        if ((accountName != null) && (accountName == my_accounts[i].name))
            selected = 'selected="selected"';
        else
            selected = '';

        $('<option ' + selected + ' value="' + my_accounts[i].name + '">' + my_accounts[i].name + '</option>').appendTo('#my_account');
    }

  
    $('#uname').html(accountName);
}