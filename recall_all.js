function bytesToHex(arrayBuffer) {
    var bytes = new Uint8Array(arrayBuffer)
    for (var hex = [], i = 0; i < bytes.length; i++) {
        hex.push((bytes[i] >>> 4).toString(16));
        hex.push((bytes[i] & 0xF).toString(16));
    }
    return hex.join("");
}

let tsfn_ptr = null; // 用于跨线程调用JS
let msgService_Js_This_Ref = null; // 引用msgService对象
let ref_ptr_array = []; // 安抚 frida memory gc

// QQNT Windows 35341
// 下面是QQNT的一些关键rva 除此之外recall peer seq解析可能存在版本差异
let add_local_gray_tip_rva = 0x1121B4E;
let recall_grp_patch_rva = 0x25BF57F;
let add_msg_listener_rva = 0x11133F4;
let recall_grp_func_rva = 0x25BF4D3;

function callAddGrayTip(tsfn, peerUid, tip_text) {
    const napi_call_threadsafe_function = Module.findExportByName('qqnt.dll', 'napi_call_threadsafe_function');
    if (!napi_call_threadsafe_function) {
        console.log('[!] napi_call_threadsafe_function not found');
        return;
    }
    // 分配结构体：peerUid和tip_text都为utf8字符串
    const peerUidBuf = Memory.allocUtf8String(peerUid);
    const tipTextBuf = Memory.allocUtf8String(tip_text);
    // 结构体：{ peerUidPtr, tipTextPtr }
    const structBuf = Memory.alloc(Process.pointerSize * 2);
    structBuf.writePointer(peerUidBuf);
    structBuf.add(Process.pointerSize).writePointer(tipTextBuf);
    ref_ptr_array.push(structBuf, peerUidBuf, tipTextBuf);// fake frida memory gc

    const napi_call_threadsafe_function_fn = new NativeFunction(
        napi_call_threadsafe_function, 'int',
        ['pointer', 'pointer', 'int']
    );
    const status = napi_call_threadsafe_function_fn(tsfn, structBuf, 0);
    if (status !== 0) {
        console.log('[!] napi_call_threadsafe_function failed:', status);
    }
}

function main() {
    // 1. wrapper.node获取基址
    var baseAddr;
    while (true) {
        baseAddr = Module.findBaseAddress('wrapper.node');
        if (baseAddr != null) break;
    }
    console.log('[+] wrapper.node baseAddr: ' + baseAddr);

    // jz -> jnz 去掉撤回通知逻辑
    const patchAddr = baseAddr.add(recall_grp_patch_rva);
    console.log("patchAddr:", patchAddr);
    Memory.protect(patchAddr, 1, 'rwx');
    const origByte = patchAddr.readU8();
    if (origByte !== 0x74) {
        console.log('警告：目标地址不是jz指令（0x74），实际为:', origByte.toString(16));
    } else {
        // 5. 写入0x75（jnz）
        patchAddr.writeU8(0x75);
        console.log('已将jz(0x74)修改为jnz(0x75)');
    }

    var napi_create_threadsafe_function = Module.findExportByName('qqnt.dll', 'napi_create_threadsafe_function');
    var napi_call_function = Module.findExportByName('qqnt.dll', 'napi_call_function');
    var napi_get_cb_info = Module.findExportByName('qqnt.dll', 'napi_get_cb_info');
    var napi_create_object = Module.findExportByName('qqnt.dll', 'napi_create_object');
    var napi_create_string_utf8 = Module.findExportByName('qqnt.dll', 'napi_create_string_utf8');
    var napi_set_named_property = Module.findExportByName('qqnt.dll', 'napi_set_named_property');
    var napi_get_boolean = Module.findExportByName('qqnt.dll', 'napi_get_boolean');
    var napi_create_function = Module.findExportByName('qqnt.dll', 'napi_create_function');
    var napi_get_named_property = Module.findExportByName('qqnt.dll', 'napi_get_named_property');
    var napi_create_reference = Module.findExportByName('qqnt.dll', 'napi_create_reference');
    var napi_get_reference_value = Module.findExportByName('qqnt.dll', 'napi_get_reference_value');
    var napi_create_reference_fn = new NativeFunction(
        napi_create_reference, 'int',
        ['pointer', 'pointer', 'uint', 'pointer']
    );
    var napi_get_reference_value_fn = new NativeFunction(
        napi_get_reference_value, 'int',
        ['pointer', 'pointer', 'pointer']
    );
    // 3. 构造NativeFunction对象
    var napi_get_cb_info_fn = new NativeFunction(
        napi_get_cb_info, 'int',
        ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer']
    );
    var napi_create_object_fn = new NativeFunction(
        napi_create_object, 'int',
        ['pointer', 'pointer']
    );
    var napi_create_string_utf8_fn = new NativeFunction(
        napi_create_string_utf8, 'int',
        ['pointer', 'pointer', 'ulong', 'pointer']
    );
    var napi_set_named_property_fn = new NativeFunction(
        napi_set_named_property, 'int',
        ['pointer', 'pointer', 'pointer', 'pointer']
    );
    var napi_get_boolean_fn = new NativeFunction(
        napi_get_boolean, 'int',
        ['pointer', 'int', 'pointer']
    );
    var napi_call_function_fn = new NativeFunction(
        napi_call_function, 'int',
        ['pointer', 'pointer', 'pointer', 'uint', 'pointer', 'pointer']
    );
    var napi_create_function_fn = new NativeFunction(
        napi_create_function, 'int',
        ['pointer', 'pointer', 'size_t', 'pointer', 'pointer', 'pointer']
    );
    var napi_get_named_property_fn = new NativeFunction(
        napi_get_named_property, 'int',
        ['pointer', 'pointer', 'pointer', 'pointer']
    );

    var napi_create_int32 = Module.findExportByName('qqnt.dll', 'napi_create_int32'); // 新增
    var napi_create_int32_fn = new NativeFunction( // 新增
        napi_create_int32, 'int',
        ['pointer', 'int', 'pointer']
    );
    if (!napi_create_threadsafe_function) {
        console.log('[!] napi_create_threadsafe_function not found');
        return;
    }
    const napi_create_threadsafe_function_fn = new NativeFunction(
        napi_create_threadsafe_function, 'int',
        [
            'pointer', // env
            'pointer', // func
            'pointer', // async_resource
            'pointer', // async_resource_name
            'size_t',  // max_queue_size
            'int',     // initial_thread_count
            'pointer', // thread_finalize_data
            'pointer', // thread_finalize_cb
            'pointer', // context
            'pointer', // call_js_cb
            'pointer'  // result
        ]
    );
    var native_func_addr = baseAddr.add(add_local_gray_tip_rva);
    var then_callback = new NativeCallback(function (env, info) {
        // 获取回调参数
        var argc_ptr = Memory.alloc(8);
        argc_ptr.writeU64(1);
        var argv_ptr = Memory.alloc(Process.pointerSize);
        var this_ptr = Memory.alloc(Process.pointerSize);
        napi_get_cb_info_fn(env, info, argc_ptr, argv_ptr, this_ptr, ptr(0));
        var result_val = argv_ptr.readPointer();

        // 获取全局对象 globalThis
        var global_name = Memory.allocUtf8String("globalThis");
        var global_ptr = Memory.alloc(Process.pointerSize);
        var status_global = napi_get_named_property_fn(env, env /* 这里用env作为global对象指针可能不对，需用napi_get_global */, global_name, global_ptr);

        // 如果有napi_get_global，优先用
        var napi_get_global = Module.findExportByName('qqnt.dll', 'napi_get_global');
        if (napi_get_global) {
            var napi_get_global_fn = new NativeFunction(
                napi_get_global, 'int',
                ['pointer', 'pointer']
            );
            status_global = napi_get_global_fn(env, global_ptr);
        }
        var global_obj = global_ptr.readPointer();

        // 获取JSON对象
        var json_name = Memory.allocUtf8String("JSON");
        var json_ptr = Memory.alloc(Process.pointerSize);
        var status_json = napi_get_named_property_fn(env, global_obj, json_name, json_ptr);
        var json_obj = json_ptr.readPointer();

        // 获取stringify函数
        var stringify_name = Memory.allocUtf8String("stringify");
        var stringify_ptr = Memory.alloc(Process.pointerSize);
        var status_stringify = napi_get_named_property_fn(env, json_obj, stringify_name, stringify_ptr);
        var stringify_fn = stringify_ptr.readPointer();

        // 调用stringify(result_val)
        var stringify_argv = Memory.alloc(Process.pointerSize);
        stringify_argv.writePointer(result_val);
        var stringify_result_ptr = Memory.alloc(Process.pointerSize);
        var status_call = napi_call_function_fn(
            env,
            json_obj,
            stringify_fn,
            1,
            stringify_argv,
            stringify_result_ptr
        );
        if (status_call === 0) {
            // 获取字符串内容
            var napi_get_value_string_utf8 = Module.findExportByName('qqnt.dll', 'napi_get_value_string_utf8');
            if (napi_get_value_string_utf8) {
                var napi_get_value_string_utf8_fn = new NativeFunction(
                    napi_get_value_string_utf8, 'int',
                    ['pointer', 'pointer', 'pointer', 'size_t', 'pointer']
                );
                var buf = Memory.alloc(1024);
                var copied = Memory.alloc(8);
                napi_get_value_string_utf8_fn(env, stringify_result_ptr.readPointer(), buf, 1023, copied);
                var jsStr = buf.readUtf8String();
                console.log('[Promise result as JSON] ' + jsStr);
            }
        } else {
            console.log('[!] JSON.stringify call failed: ' + status_call);
        }
        return 0;
    }, 'int', ['pointer', 'pointer']);
    // 6. 创建then回调JS函数
    function createThenCallback(env) {
        var cb_ptr = Memory.alloc(Process.pointerSize);
        var cb_name = Memory.allocUtf8String("thenCallback");
        var status = napi_create_function_fn(
            env,
            cb_name,
            12,
            then_callback,
            ptr(0),
            cb_ptr
        );
        if (status !== 0) {
            console.log('[!] napi_create_function (thenCallback) failed: ' + status);
            return null;
        }
        return cb_ptr.readPointer();
    }
    const js_callback = new NativeCallback(function (env, js_cb, context, data) {
        console.log('[+] cb env:', env);
        console.log('[TSFN JS Callback] 收到回调');

        var groupId = "819085771";
        var tip_text = "Frida Hook QQNT By NapCat";
        if (!data.isNull()) {
            try {
                const peerUidPtr = data.readPointer();
                const tipTextPtr = data.add(Process.pointerSize).readPointer();
                groupId = peerUidPtr.readUtf8String();
                tip_text = tipTextPtr.readUtf8String();
                //删除数组ref_ptr_array中对应元素
                if (ref_ptr_array.indexOf(peerUidPtr) !== -1) {
                    ref_ptr_array.splice(ref_ptr_array.indexOf(peerUidPtr), 1);
                }
                if (ref_ptr_array.indexOf(tipTextPtr) !== -1) {
                    ref_ptr_array.splice(ref_ptr_array.indexOf(tipTextPtr), 1);
                }
                // 回收data
                if (ref_ptr_array.indexOf(data) !== -1) {
                    ref_ptr_array.splice(ref_ptr_array.indexOf(data), 1);
                }
            } catch (e) {
                console.log('[!] 解析data失败:', e);
            }
        }

        var obj1_ptr = Memory.alloc(Process.pointerSize);
        napi_create_object_fn(env, obj1_ptr);
        var obj1 = obj1_ptr.readPointer();

        var key_chatType = Memory.allocUtf8String("chatType");
        var val_chatType_ptr = Memory.alloc(Process.pointerSize);
        var status_chatType = napi_create_int32_fn( // 改为创建数字2
            env,
            2,
            val_chatType_ptr
        );
        if (status_chatType !== 0) {
            console.log('[!] napi_create_int32_fn(chatType) failed: ' + status_chatType);
        }
        var val_chatType = val_chatType_ptr.readPointer();
        napi_set_named_property_fn(env, obj1, key_chatType, val_chatType);

        var key_guildId = Memory.allocUtf8String("guildId");
        var guildIdStr = "";
        var guildIdBuf = Memory.allocUtf8String(guildIdStr);
        var guildIdLen = guildIdStr.length;
        var val_guildId_ptr = Memory.alloc(Process.pointerSize);
        var status_guildId = napi_create_string_utf8_fn(
            env,
            guildIdBuf,
            guildIdLen,
            val_guildId_ptr
        );
        if (status_guildId !== 0) {
            console.log('[!] napi_create_string_utf8_fn(guildId) failed: ' + status_guildId);
        }
        var val_guildId = val_guildId_ptr.readPointer();
        napi_set_named_property_fn(env, obj1, key_guildId, val_guildId);

        var key_peerUid = Memory.allocUtf8String("peerUid");
        var peerUidStr = groupId;//群号
        var peerUidBuf = Memory.allocUtf8String(peerUidStr);
        var peerUidLen = peerUidStr.length;
        var val_peerUid_ptr = Memory.alloc(Process.pointerSize);
        var status_peerUid = napi_create_string_utf8_fn(
            env,
            peerUidBuf,
            peerUidLen,
            val_peerUid_ptr
        );
        if (status_peerUid !== 0) {
            console.log('[!] napi_create_string_utf8_fn(peerUid) failed: ' + status_peerUid);
        }
        var val_peerUid = val_peerUid_ptr.readPointer();
        napi_set_named_property_fn(env, obj1, key_peerUid, val_peerUid);

        // 第二个object参数
        var obj2_ptr = Memory.alloc(Process.pointerSize);
        napi_create_object_fn(env, obj2_ptr);
        var obj2 = obj2_ptr.readPointer();

        var key_busiId = Memory.allocUtf8String("busiId");
        var val_busiId_ptr = Memory.alloc(Process.pointerSize);
        var status_busiId = napi_create_int32_fn( // 改为创建数字2201
            env,
            2201,
            val_busiId_ptr
        );
        if (status_busiId !== 0) {
            console.log('[!] napi_create_int32_fn(busiId) failed: ' + status_busiId);
        }
        var val_busiId = val_busiId_ptr.readPointer();
        napi_set_named_property_fn(env, obj2, key_busiId, val_busiId);

        var key_jsonStr = Memory.allocUtf8String("jsonStr");
        var jsonStr = JSON.stringify({ "align": "center", "items": [{ "txt": tip_text, "type": "nor" }] });
        var jsonStrBuf = Memory.allocUtf8String(jsonStr);
        var jsonStrLen = jsonStr.length;
        var val_jsonStr_ptr = Memory.alloc(Process.pointerSize);
        var status_jsonStr = napi_create_string_utf8_fn(
            env,
            jsonStrBuf,
            jsonStrLen,
            val_jsonStr_ptr
        );
        if (status_jsonStr !== 0) {
            console.log('[!] napi_create_string_utf8_fn(jsonStr) failed: ' + status_jsonStr);
        }
        var val_jsonStr = val_jsonStr_ptr.readPointer();
        napi_set_named_property_fn(env, obj2, key_jsonStr, val_jsonStr);

        var key_recentAbstract = Memory.allocUtf8String("recentAbstract");
        var recentAbstractStr = tip_text;
        var recentAbstractBuf = Memory.allocUtf8String(recentAbstractStr);
        var recentAbstractLen = recentAbstractStr.length;
        var val_recentAbstract_ptr = Memory.alloc(Process.pointerSize);
        var status_recentAbstract = napi_create_string_utf8_fn(
            env,
            recentAbstractBuf,
            recentAbstractLen,
            val_recentAbstract_ptr
        );
        if (status_recentAbstract !== 0) {
            console.log('[!] napi_create_string_utf8_fn(recentAbstract) failed: ' + status_recentAbstract);
        }
        var val_recentAbstract = val_recentAbstract_ptr.readPointer();
        napi_set_named_property_fn(env, obj2, key_recentAbstract, val_recentAbstract);

        var key_isServer = Memory.allocUtf8String("isServer");
        var bool_isServer_ptr = Memory.alloc(Process.pointerSize);
        napi_get_boolean_fn(env, 0, bool_isServer_ptr);
        var bool_isServer = bool_isServer_ptr.readPointer();
        napi_set_named_property_fn(env, obj2, key_isServer, bool_isServer);
        // 下面可删除
        try {
            // 获取 globalThis
            var global_ptr = Memory.alloc(Process.pointerSize);
            var napi_get_global = Module.findExportByName('qqnt.dll', 'napi_get_global');
            var global_obj;
            if (napi_get_global) {
                var napi_get_global_fn = new NativeFunction(
                    napi_get_global, 'int',
                    ['pointer', 'pointer']
                );
                var status_global = napi_get_global_fn(env, global_ptr);
                global_obj = global_ptr.readPointer();
            } else {
                var global_name = Memory.allocUtf8String("globalThis");
                var status_global = napi_get_named_property_fn(env, env, global_name, global_ptr);
                global_obj = global_ptr.readPointer();
            }

            // 获取 JSON 对象
            var json_name = Memory.allocUtf8String("JSON");
            var json_ptr = Memory.alloc(Process.pointerSize);
            var status_json = napi_get_named_property_fn(env, global_obj, json_name, json_ptr);
            var json_obj = json_ptr.readPointer();

            // 获取 stringify 函数
            var stringify_name = Memory.allocUtf8String("stringify");
            var stringify_ptr = Memory.alloc(Process.pointerSize);
            var status_stringify = napi_get_named_property_fn(env, json_obj, stringify_name, stringify_ptr);
            var stringify_fn = stringify_ptr.readPointer();

            // 调用 stringify(obj2)
            var stringify_argv = Memory.alloc(Process.pointerSize);
            stringify_argv.writePointer(obj2);
            var stringify_result_ptr = Memory.alloc(Process.pointerSize);
            var status_call = napi_call_function_fn(
                env,
                json_obj,
                stringify_fn,
                1,
                stringify_argv,
                stringify_result_ptr
            );
            if (status_call === 0) {
                // 获取字符串内容
                var napi_get_value_string_utf8 = Module.findExportByName('qqnt.dll', 'napi_get_value_string_utf8');
                if (napi_get_value_string_utf8) {
                    var napi_get_value_string_utf8_fn = new NativeFunction(
                        napi_get_value_string_utf8, 'int',
                        ['pointer', 'pointer', 'pointer', 'size_t', 'pointer']
                    );
                    var buf = Memory.alloc(1024);
                    var copied = Memory.alloc(8);
                    napi_get_value_string_utf8_fn(env, stringify_result_ptr.readPointer(), buf, 1023, copied);
                    var jsStr = buf.readUtf8String();
                    console.log('[obj2 as JSON] ' + jsStr);
                }
            } else {
                console.log('[!] JSON.stringify(obj2) call failed: ' + status_call);
            }
        } catch (e) {
            console.log('[!] Exception during obj2 JSON output: ' + e);
        }
        // 两个bool参数
        var bool1_ptr = Memory.alloc(Process.pointerSize);
        var bool2_ptr = Memory.alloc(Process.pointerSize);
        napi_get_boolean_fn(env, 1, bool1_ptr);
        napi_get_boolean_fn(env, 1, bool2_ptr);
        var bool1 = bool1_ptr.readPointer();
        var bool2 = bool2_ptr.readPointer();

        // argv
        var argv = Memory.alloc(Process.pointerSize * 4);
        argv.add(0).writePointer(obj1);
        argv.add(Process.pointerSize).writePointer(obj2);
        argv.add(Process.pointerSize * 2).writePointer(bool1);
        argv.add(Process.pointerSize * 3).writePointer(bool2);

        var func_ptr = Memory.alloc(Process.pointerSize);
        var func_name = Memory.allocUtf8String("nativeFunc");
        var create_status = napi_create_function_fn(
            env,
            func_name,
            10,
            native_func_addr,
            ptr(0),
            func_ptr
        );
        if (create_status !== 0) {
            console.log('[!] napi_create_function failed: ' + create_status);
            return;
        }
        var func = func_ptr.readPointer();
        // 调用napi_call_function，返回Promise
        var js_this_ref_ptr = Memory.alloc(Process.pointerSize);
        var js_ref_status = napi_get_reference_value_fn(
            env,
            msgService_Js_This_Ref,
            js_this_ref_ptr
        );
        if (js_ref_status !== 0) {
            console.log('[!] napi_get_reference_value failed: ' + js_ref_status);
            return;
        }
        var result_ptr = Memory.alloc(Process.pointerSize);
        var call_status = napi_call_function_fn(
            env,
            js_this_ref_ptr.readPointer(),
            func,
            4,
            argv,
            result_ptr
        );
        console.log('[*] napi_call_function status: ' + call_status);
        var promise_obj = result_ptr.readPointer();
        console.log('[*] napi_call_function result (Promise): ' + promise_obj);
        // 获取Promise的then方法
        var key_then = Memory.allocUtf8String("then");
        var then_fn_ptr = Memory.alloc(Process.pointerSize);
        var get_then_status = napi_get_named_property_fn(
            env,
            promise_obj,
            key_then,
            then_fn_ptr
        );
        if (get_then_status !== 0) {
            console.log('[!] napi_get_named_property_fn(then) failed: ' + get_then_status);
            return;
        }
        var then_fn = then_fn_ptr.readPointer();

        // 创建then回调
        var then_cb = createThenCallback(env);
        if (!then_cb) return;

        // 调用then方法
        var then_argv = Memory.alloc(Process.pointerSize);
        then_argv.writePointer(then_cb);
        var then_result_ptr = Memory.alloc(Process.pointerSize);
        var then_call_status = napi_call_function_fn(
            env,
            promise_obj,
            then_fn,
            1,
            then_argv,
            then_result_ptr
        );
        console.log('[*] napi_call_function (then) status: ' + then_call_status);
        return 0;
    }, 'int', ['pointer', 'pointer', 'pointer', 'pointer']);

    let add_msg_listener = baseAddr.add(add_msg_listener_rva);
    Interceptor.attach(add_msg_listener, {
        onEnter: function (args) {
            const napi_env_ptr = args[0];
            var this_arg_ptr = Memory.alloc(Process.pointerSize);
            napi_get_cb_info_fn(
                args[0], args[1],
                ptr(0), ptr(0),
                this_arg_ptr, ptr(0)
            );

            var ref_ptr = Memory.alloc(Process.pointerSize);
            var ref_create_status = napi_create_reference_fn(
                napi_env_ptr,
                this_arg_ptr.readPointer(), // 传入this对象
                1, // refcount
                ref_ptr
            );
            if (ref_create_status === 0) {
                msgService_Js_This_Ref = ref_ptr.readPointer();
                console.log('[+] msgService_Js_This_Ref 持久化:', msgService_Js_This_Ref);
            } else {
                console.log('[!] napi_create_reference failed:', ref_create_status);
            }

            console.log('[+] this_arg_ptr:', this_arg_ptr);
            console.log('[+] env_ptr:', napi_env_ptr);
            const async_resource_name = Memory.allocUtf8String("frida_tsfn");
            const tsfn_result_ptr = Memory.alloc(Process.pointerSize);
            const status = napi_create_threadsafe_function_fn(
                napi_env_ptr,
                ptr(0), // func: NULL
                ptr(0), // async_resource
                async_resource_name,
                0,      // max_queue_size
                1,      // initial_thread_count
                ptr(0), // thread_finalize_data
                ptr(0), // thread_finalize_cb
                ptr(0), // context
                js_callback, // call_js_cb
                tsfn_result_ptr
            );
            if (status !== 0) {
                console.log('[!] napi_create_threadsafe_function failed:', status);
                return;
            }
            tsfn_ptr = tsfn_result_ptr.readPointer();
            console.log('[+] Created ThreadSafeFunction:', tsfn_ptr);
        },
        onLeave: function (retval) {

        }
    });
    // [Msg] on grp recall nfy ! frm:{} to:{}, pr:{} seq:{} rd:{} t:{} op_uid:{} op_t:{} is_off:{} trl_flag:{}
    // 解析撤回事件
    var hookAddr = baseAddr.add(recall_grp_func_rva);
    console.log("hookAddr:", hookAddr);
    Interceptor.attach(hookAddr, {
        onEnter: function (args) {
            const peer_ptr = this.context.rbp.add(0x30);
            const peer = peer_ptr.add(0x1).readUtf8String();
            console.log("=> Group Recall");
            console.log("peer:", peer);

            const seq_ptr = this.context.rbp.add(0x80);
            const seq = seq_ptr.readU64();
            console.log("seq:", seq);
            if (tsfn_ptr) {
                let tip_text = "Sequence: " + seq + " has been recalled";
                // 发送回调
                callAddGrayTip(tsfn_ptr, peer, tip_text);
            }
            console.log("<=");
        }
    });
}

main();