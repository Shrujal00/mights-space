'use strict';

/*
 * Hooks for observing an Android sample inside the emulator.
 *
 * Every hook does three things and nothing else: call the original method,
 * report what it saw, and return the original result. It must never change what
 * the app does. A hook that alters behaviour would make the report a
 * description of the instrumentation rather than of the sample.
 *
 * Row counts matter more than anything else here. "Read the SMS inbox" is
 * something a messaging app does too; "read 247 messages from the SMS inbox"
 * is the sentence an investigator can put in front of a magistrate. Wherever a
 * count is available it is recorded.
 *
 * Every hook body is wrapped in try/catch. A sample that trips one hook must
 * not take down the rest of the instrumentation, and a hook that throws inside
 * the app's own call stack would crash the sample and end the run.
 */

function emit(category, action, target, detail, bytes, count) {
  try {
    var message = {
      ts: Date.now(),
      category: category,
      action: action,
      target: target,
      detail: detail || ''
    };
    if (typeof bytes === 'number' && isFinite(bytes)) {
      message.bytes = bytes;
    }
    /* Sent as a number as well as in the text, because the report must never
     * recover a figure by parsing a sentence. A query that came back empty is
     * reported as 0, which is what stops it being called a theft. */
    if (typeof count === 'number' && isFinite(count) && count >= 0) {
      message.count = count;
    }
    send(message);
  } catch (e) {
    /* Reporting must never break the run. */
  }
}

/* Which store of personal data a content URI refers to, or null if it is not
 * one we report on. Matching is on the authority, so a sample cannot dodge the
 * hook by appending path segments. */
function personalDataAt(uri) {
  if (uri === null || uri === undefined) {
    return null;
  }
  var text = uri.toString().toLowerCase();
  if (text.indexOf('sms') !== -1 || text.indexOf('mms') !== -1) return 'SMS inbox';
  if (text.indexOf('contacts') !== -1) return 'contacts';
  if (text.indexOf('call_log') !== -1) return 'call log';
  if (text.indexOf('calendar') !== -1) return 'calendar';
  if (text.indexOf('media') !== -1) return 'stored photos and media';
  return null;
}

/* Rows a query returned, or null when it could not be counted. Null and zero
 * mean different things downstream and must not be conflated. */
function rowsIn(cursor) {
  if (cursor === null || cursor === undefined) {
    return null;
  }
  try {
    /* getCount() does not move the cursor, so the app still reads every row. */
    return cursor.getCount();
  } catch (e) {
    return null;
  }
}

function describeRows(count) {
  if (count === null) {
    return '';
  }
  return count + (count === 1 ? ' record' : ' records');
}

/* Hook every overload of a method, tolerating classes absent on this device. */
function hook(className, methodName, wrap) {
  try {
    var target = Java.use(className);
    var method = target[methodName];
    if (method === undefined) {
      return;
    }
    method.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var result = overload.apply(this, arguments);
        try {
          wrap.call(this, arguments, result);
        } catch (e) {
          /* Observation failed; the app's own call already succeeded. */
        }
        return result;
      };
    });
  } catch (e) {
    /* Not present on this API level. Nothing to observe. */
  }
}

Java.perform(function () {
  emit('process', 'started', 'the application', 'launched under instrumentation');

  /* --- Reading the victim's data ------------------------------------- */

  hook('android.content.ContentResolver', 'query', function (args, cursor) {
    var store = personalDataAt(args[0]);
    if (store !== null) {
      var rows = rowsIn(cursor);
      emit('data-access', 'read', store, describeRows(rows), undefined, rows);
    }
  });

  hook('android.telephony.TelephonyManager', 'getDeviceId', function (args, value) {
    emit('data-access', 'read', 'the phone hardware identifier (IMEI)', '');
  });

  hook('android.telephony.TelephonyManager', 'getSubscriberId', function (args, value) {
    emit('data-access', 'read', 'the SIM subscriber identifier (IMSI)', '');
  });

  hook('android.telephony.TelephonyManager', 'getLine1Number', function (args, value) {
    emit('data-access', 'read', "the phone's own number", '');
  });

  hook('android.location.LocationManager', 'getLastKnownLocation', function (args, value) {
    emit('data-access', 'read', "the phone's location", '');
  });

  hook('android.content.pm.PackageManager', 'getInstalledPackages', function (args, value) {
    var detail = '';
    try {
      detail = value.size() + ' apps';
    } catch (e) { /* older signature */ }
    emit('data-access', 'read', 'the list of installed apps', detail);
  });

  /* --- Sending it somewhere ------------------------------------------ */

  hook('android.telephony.SmsManager', 'sendTextMessage', function (args) {
    var destination = args[0] === null ? 'an unknown number' : args[0].toString();
    var body = '';
    try {
      body = args[2] === null ? '' : args[2].toString();
    } catch (e) { /* not a string overload */ }
    emit('network', 'sent', 'a text message to ' + destination, '', body.length);
  });

  hook('android.telephony.SmsManager', 'sendMultipartTextMessage', function (args) {
    var destination = args[0] === null ? 'an unknown number' : args[0].toString();
    emit('network', 'sent', 'a multipart text message to ' + destination, '');
  });

  /* java.net covers HttpURLConnection and, underneath, most HTTP clients. The
   * URL is taken at connect() because that is the point the address is fixed. */
  hook('java.net.URL', 'openConnection', function (args) {
    emit('network', 'opened', this.toString(), 'HTTP connection');
  });

  hook('java.net.Socket', 'connect', function (args) {
    var where = args[0] === null ? 'an unknown address' : args[0].toString();
    emit('network', 'connected', where.replace(/^\//, ''), '');
  });

  /* OkHttp, if the app bundles it. Retrofit sits on top of OkHttp, so hooking
   * the call layer catches both. */
  try {
    var RealCall = Java.use('okhttp3.internal.connection.RealCall');
    RealCall.execute.implementation = function () {
      var response = this.execute();
      try {
        emit('network', 'requested', this.request().url().toString(), 'OkHttp');
      } catch (e) { /* nothing to report */ }
      return response;
    };
  } catch (e) {
    /* App does not bundle OkHttp. */
  }

  /* --- Loading more code at runtime ---------------------------------- */

  /* A dropper ships almost empty and fetches its real payload after install,
   * which is how it passes store review and static scanning alike. */
  try {
    var DexClassLoader = Java.use('dalvik.system.DexClassLoader');
    DexClassLoader.$init.overloads.forEach(function (overload) {
      overload.implementation = function () {
        emit('process', 'loaded', String(arguments[0]), 'extra code loaded at runtime');
        return overload.apply(this, arguments);
      };
    });
  } catch (e) { /* not present */ }

  try {
    var BaseDexClassLoader = Java.use('dalvik.system.BaseDexClassLoader');
    BaseDexClassLoader.$init.overloads.forEach(function (overload) {
      overload.implementation = function () {
        emit('process', 'loaded', String(arguments[0]), 'extra code loaded at runtime');
        return overload.apply(this, arguments);
      };
    });
  } catch (e) { /* not present */ }

  hook('java.lang.Runtime', 'exec', function (args) {
    emit('process', 'ran', String(args[0]), 'shell command');
  });

  /* --- Writing to its own storage ------------------------------------ */

  try {
    var FileOutputStream = Java.use('java.io.FileOutputStream');
    FileOutputStream.$init.overloads.forEach(function (overload) {
      overload.implementation = function () {
        try {
          var path = String(arguments[0]);
          /* Only the app's private storage. Framework writes elsewhere are
           * constant background noise and would drown the timeline. */
          if (path.indexOf('/data/data/') !== -1 || path.indexOf('/data/user/') !== -1) {
            emit('file', 'wrote', path, '');
          }
        } catch (e) { /* not a path overload */ }
        return overload.apply(this, arguments);
      };
    });
  } catch (e) { /* not present */ }

  /* --- Hiding what it sends ------------------------------------------ */

  hook('javax.crypto.Cipher', 'doFinal', function (args, result) {
    var size = 0;
    try {
      size = result === null ? 0 : result.length;
    } catch (e) { /* not a byte[] overload */ }
    emit('crypto', 'encrypted', 'data before sending', '', size);
  });

  send({ ts: Date.now(), category: 'process', action: 'ready', target: 'instrumentation', detail: 'all hooks installed' });
});
