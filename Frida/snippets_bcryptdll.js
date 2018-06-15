pointer = Module.findExportByName('bcrypt.dll','BCryptGenerateSymmetricKey')
Interceptor.attach(pointer, {
	onEnter: function (args) {
		//https://csrc.nist.gov/csrc/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp1328.pdf
		// args[0] == [in,out]	pointer to void - BCRYPT_ALG_HANDLE check this http://www.rdos.net/svn/tags/V9.2.5/watcom/bld/w32api/include/bcrypt.mh
		// args[1] == [out]		pointer to void - BCRYPT_KEY_HANDLE check this https://retep998.github.io/doc/winapi/bcrypt/type.BCRYPT_KEY_HANDLE.html
		// args[2] == [out]		
		console.log('hAlgorithm:	' + args[0]);
		console.log('*phKey:		' + args[1]);
		console.log('pbKeyObject:	' + args[2]);
		console.log('cbKeyObject:	' + args[3]);
		console.log('pbSecret:		' + args[4]);
		console.log('cbSecret:		' + args[5]);
		console.log('dwFlags:		' + args[6]);
		if (args[5] <= 0x1000) {
			this.outsize = args[5].toInt32();
			this.outptr = args[4];
		}
	}, onLeave: function (retval) {
		buf = Memory.readByteArray(this.outptr, this.outsize);
		console.log(hexdump(buf, { offset: 0, length: this.outsize, header: true, ansi: false }));
		console.log('---------------------------> ReturnValue: ' + retval);
	}
})



pointer = Module.findExportByName('bcrypt.dll','BCryptGenerateSymmetricKey')
Interceptor.attach(pointer, {
	onEnter: function (args) {
		console.log('hAlgorithm:	' + args[0]);
		console.log('*phKey:		' + args[1]);
		console.log('pbKeyObject:	' + args[2]);
		console.log('cbKeyObject:	' + args[3]);
		console.log('pbSecret:		' + args[4]);
		console.log('cbSecret:		' + args[5]);
		console.log('dwFlags:		' + args[6]);
		console.log('dwFlags:		' + args[7]);
		console.log('dwFlags:		' + args[8]);
		console.log('dwFlags:		' + args[9]);
		this.outsize = 16;
		this.outptr = args[4];
	}, onLeave: function (retval) {
		buf = Memory.readByteArray(this.outptr, 16);
		console.log(hexdump(buf, { offset: 0, length: this.outsize, header: true, ansi: false }));
		console.log('---------------------------> ReturnValue: ' + retval);
	}
})

pointer = Module.findExportByName('bcrypt.dll','BCryptDecrypt')
Interceptor.attach(pointer, {
	onEnter: function (args) {
		console.log('hKey:			' + args[0]);
		console.log('pbInput:		' + args[1]);
		console.log('cbInput:		' + args[2]);
		console.log('*pPaddingInfo:	' + args[3]);
		console.log('pbIV:			' + args[4]);
		console.log('cbIV:			' + args[5]);
		console.log('pbOutput:		' + args[6]);
		console.log('cbOutput:		' + args[7]);
		console.log('*pcbResult:	' + args[8]);
		console.log('dwFlags:		' + args[9]);
	}, onLeave: function (retval) {
		console.log('---------------------------> ReturnValue: ' + retval);
	}
})