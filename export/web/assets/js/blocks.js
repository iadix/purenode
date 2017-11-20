var TxpageNum = 0, addrPageNum = 0;
var blockTimer = null;
var CurrentTime = null;
var updt_blocks = null;
var busy = false;
var blk_filters = [];
var unit = 100000000;

var sent = 0;
var recv = 0;


if (!Uint8Array.prototype.slice && 'subarray' in Uint8Array.prototype)
     Uint8Array.prototype.slice = Uint8Array.prototype.subarray;

function get_tx(hash) {
    api_call('tx', '/' + hash, function (data) {
        tx = data;
        update_tx('tx_list');
    });
}


function remove_filter(i)
{
    if (i >= blk_filters.length) return;
    blk_filters.splice(i, 1);
    update_filter_list();
}

function add_block_filter(key, op, val) {
    var new_filter = key + op + val;
    var found = 0;
    for (var i = 0; i < blk_filters.length; i++)
    {
        if (blk_filters[i].indexOf(key) == 0)
        {
            var fop = blk_filters[i].substr(key.length, 1);
            found = 1;
            
            if (fop == op) {
                blk_filters[i] = new_filter;
            }
            else {
                var fval = parseInt(blk_filters[i].substr(key.length + 1, 1));
                switch(fop)
                {
                    case '>':
                        switch (op) {
                            case '<':
                                if (fval > val)
                                    blk_filters[i] = new_filter;
                                else
                                    blk_filters.push(new_filter);
                            break;
                            case '=':
                                blk_filters[i] = new_filter;
                            break;
                        }

                    break;
                    case '<':
                        switch (op) {
                          case '>':
                             if (fval < val)
                                 blk_filters[i] = new_filter;
                              else
                                 blk_filters.push(new_filter);
                           break;
                           case '=': blk_filters[i] = new_filter; break;
                        }
                    break;
                    case '=': blk_filters[i] = new_filter; break;
                }
            }
        }
    }

    if (!found)
        blk_filters.push(new_filter);
    update_filter_list();
}

var lastLastBlock = 0;


function list_block_txs(hash, pageNum) {
    api_call('txs', '?block=' + hash + '&pageNum=' + pageNum, function (data) {
        if (txs == null)
            txs = data.txs;
        else
            txs.push.apply(txs, data.txs);

        update_txs(txs, 'tx_list');

        if (txs.length < data.numtx)
            $('#txloadmore').removeProp("disabled");
        else
            $('#txloadmore').prop("disabled", true);

        $("#curtxs").html(txs.length);
        $("#totaltxs").html(data.numtx);
    });
}
function list_txs(date, pageNum) {
    api_call('txs', "?BlockDate=" + date + '&pageNum=' + pageNum, function (data) {

        if (data != null) {
            if (txs == null)
                txs = data.txs;
            else
                txs.push.apply(txs, data.txs);

            update_txs(txs, 'tx_list');


            if (txs.length < data.numtxs)
                $('#txloadmore').removeProp("disabled");
            else
                $('#txloadmore').prop("disabled", true);

            $("#curtxs").html(txs.length);
            $("#totaltxs").html(data.numtxs);
        }
        else {
            $('#txloadmore').prop("disabled", true);
            $("#curtxs").html('0');
            $("#totaltxs").html('0');
        }



    });
}

function list_blocks(date, pageNum,lastBlock) {

    var urlq = '';
    var first = 1;

    if (document.getElementById("list_table") == null) return;

    if(date!=null)
    {
        urlq = 'BlockDate=' + date ;
        first = 0;
    }

    if (pageNum > 0) {
        if (!first) urlq += '&';
        urlq += 'pageNum=' + pageNum;
        first = 0;
    }

    if (lastBlock > 0)
    {
        if (!first) urlq += '&';
        urlq += 'height<' + lastBlock;
        first = 0;
        lastLastBlock = lastBlock;
    }

    for (var i = 0; i < blk_filters.length; i++)
    {
        if (!first) urlq += '&';
        urlq += blk_filters[i];
        first = 0;
    }


    old_tbody = document.getElementById("list_table").tBodies[0];
    new_tbody = document.createElement('tbody');
    old_tbody.parentNode.replaceChild(new_tbody, old_tbody);

    api_call('blocks', '?'+urlq, function (data) {

        var mdate;

        if (data != null) {
            if (blocks == null)
                blocks = data.blocks;
            else
                blocks.push.apply(blocks, data.blocks);

            blocks.sort(function (a, b) { return (b.time - a.time); });
        }

        if (date != null) {
            CurrentTime = Math.round(new Date(date).getTime() / 1000);
            PrevTime = CurrentTime - 24 * 3600;
            NextTime = CurrentTime + 24 * 3600;

            mdate = dateConverter(CurrentTime);
            $("#blocklistdate").html(mdate);

            mdate = dateConverter(NextTime);
            $("#blocklistnext").html(mdate);

            mdate = dateConverter(PrevTime);
            $("#blocklistprev").html(mdate);
        }
        else {
            $("#blocklistdate").empty();
            $("#blocklistnext").empty();
            $("#blocklistprev").empty();
        }

        update_blocks();

        if ((blocks != null) && (data != null)) {
            $("#curblocks").html(blocks.length);
            $("#totalblocks").html(data.numblocks);

            if (data.lastblockidx > 0)
            {
                $('#searchmore').removeProp("disabled");
                $('#cursearch').removeProp("disabled");
                $('#cursearch').val(data.lastblockidx);
            }
            else
            {
                $('#cursearch').prop("disabled", true);
                $('#searchmore').prop("disabled", true);
                $('#cursearch').val('0');
            }

            if (blocks.length < data.numblocks)
                $('#blkloadmore').removeProp("disabled");
            else
                $('#blkloadmore').prop("disabled", true);
        }
        else
        {
            $('#searchmore').prop("disabled", true);
            $('#cursearch').val('');
            $("#curblocks").html('0');
            $("#totalblocks").html('0');
            $('#blkloadmore').prop("disabled", true);
        }
            
    });
}


function update_blocks_calendar(d,reload) {
    var m = $("#block_m").val();
    var y = $("#block_y").val();

    if (m.length < 2)
        m = '0' + m.toString(10);

    if (d < 10)
        d = '0' + d.toString(10);

    $("#block_d").val(d);

    $('#cal_div').load(site_url + '/ico/get_cal/' + lang + '/' + y + '/' + m + '/' + d);
    if (reload) {
        
        blk_page_idx = 0;
        tx_page_idx = 0;
        blocks = null;
        list_blocks(y + '-' + m + '-' + d, 0,0);
        txs = null;
        list_txs(y + '-' + m + '-' + d, 0);
    }
}
function setCalDate(UNIX_timestamp) {
    var a = new Date(UNIX_timestamp * 1000);
    var months = ['01', '02', '03', '04', '05', '06', '07', '08', '09', '10', '11', '12'];
    var year = a.getFullYear();
    var month = months[a.getMonth()];
    var day;

    if (a.getDate() < 10)
        day = '0' + a.getDate();
    else
        day = a.getDate();

    $("#block_y").val(year);
    $("#block_m").val(month);
    $("#block_d").val(day);

    update_blocks_calendar(day,0);
}
function get_lasttxs() {
    api_call('txs', '', function (data) {
        TxpageNum = 0;
        lastblock = data;
        if (txs == null)
            txs = data.txs;
        else
            txs.push.apply(txs, data.txs);

        update_txs(txs, 'tx_list');

        $('#txloadmore').removeProp("disabled");
        $("#curtxs").html(txs.length);
        $("#totaltxs").html('--');
    });
}

function get_lastblock() {
    api_call('block', '', function (data) {
        var tdate;
        var PrevTime, NextTime;
        var date;
        lastblock = data;

        if(document.getElementById('inline'))
            setCalDate(lastblock.time);

        tdate = dateConverter(lastblock.time);
        $("#blocklistdate").html(tdate);

        PrevTime = data.time - 24 * 3600;
        NextTime = data.time + 24 * 3600;

        date = dateConverter(NextTime);
        $("#blocklistnext").html(date);

        date = dateConverter(PrevTime);
        $("#blocklistprev").html(date);
      
        updateblock(data);
        blocks = null;
        txs = null;
        list_blocks(tdate, blk_page_idx,0);
    });
}


function list_addr_txs(addr, pageNum) {
    api_call('txs', '?address=' + addr + '&pageNum=' + pageNum, function (data) {

        if (txs == null)
            txs = data.txs;
        else
            txs.push.apply(txs, data.txs);

        txs.sort(function (a, b) { return (b.blocktime - a.blocktime); });

        update_addr_txs('tx_list');

        $("#Transactions").html(data.numtx);
        $("#currentaddrtx").html(txs.length);
        $("#totaladdrtx").html(data.numtx);

        if (txs.length < data.numtx)
            $('#loadmore').removeProp("disabled");
        else
            $('#loadmore').prop("disabled", true);
            

        $('#address').html(addr);
    });
}

function new_blocks() {
    api_call('blocks', "?SinceBlock=" + blocks[0].hash, function (data) {
        updt_blocks = data.blocks;
        $("#newblocks").html(updt_blocks.length);
    });
}

function selectAddress(saddr) {
    addrPageNum = 0;
    currentAddr = saddr.toString();
    addrstxs = null;
    list_addr_txs(currentAddr, addrPageNum);
    $("#address_list").html(currentAddr);

}
function selectBlock(hash) {

    if (selectedhash != null) {
        $('#block_' + selectedhash).removeClass("selected");
        selectedhash = null;
    }

    api_call('block', '/' + hash, function (blk_data) {
        blk_page_idx = 0;
        block = blk_data;
        blocks = new Array(block);
        updateblock(block);
        update_blocks();

        $('#blkloadmore').prop('disabled', true);
        $("#curblocks").html("1");
        $("#totalblocks").html("1");

        selectedhash = block.hash;
        $('#block_' + selectedhash).addClass("selected");
        $('#search_bar').val(block.hash);
    });
}

function SelectTx(hash) {
    api_call('tx', '/' + hash, function (tx_data) {
        tx = tx_data;
        txs = new Array(tx);
        update_txs(txs, 'tx_list');

        $('#txloadmore').prop("disabled", true);
        $("#curtxs").html("1");
        $("#totaltxs").html("1");

        $('#search_bar').val(tx.txid);
        if (selectedhash != null) {
            $('#block_' + selectedhash).removeClass("selected");
            selectedhash = null;
        }

        api_call('block', '/' + tx.blockhash, function (blk_data) {
                block = blk_data;
                blocks = new Array(block);
                updateblock(block);
                update_blocks();

                $('#blkloadmore').prop('disabled', true);
                $("#curblocks").html("1");
                $("#totalblocks").html("1");
                selectedhash = block.hash;
                $('#block_' + selectedhash).addClass("selected");
        });
    });
}


function selectBlockTxs(hash) {
    if (selectedhash != null) {
        $('#block_' + selectedhash).removeClass("selected");
        selectedhash = null;
    }

    api_call('block', '/' + hash, function (blk_data) {
        block = blk_data;
        blocks = new Array(block);
        tx_page_idx = 0;
        blk_page_idx = 0;
        updateblock(block);
        update_blocks();

        txs = null;
        list_block_txs(block.hash, TxpageNum);
        
        $('#blkloadmore').prop('disabled', true);
        $("#curblocks").html("1");
        $("#totalblocks").html("1");
        $('#search_bar').val(block.hash);
        selectedhash = block.hash;
        $('#block_' + hash).addClass("selected");
    });
}

