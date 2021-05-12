var slideToggler,
    trigger,
    bind = function(fn, me) {
        return function() {
            return fn.apply(me, arguments);
        };
    },
    indexOf = [].indexOf || function(item) {
        for (var i = 0, length = this.length; i < length; i++) {
            if (i in this && this[i] === item) {
                return i;
            }
        }

        return -1;
    };

slideToggler = (function() {
    function slideToggler(el1) {
        if (el1) {
            this.el = el1;
            this.toggle = bind(this.toggle, this);
            this.height = this.getHeight();
        } else {
            return;
        }
    }

    slideToggler.prototype.getHeight = function() {
        var clone;

        if (this.el.clientHeight > 10) {
            return this.el.clientHeight;
        }

        clone = this.el.cloneNode(true);
        clone.style.cssText = 'position: absolute; visibility: hidden; display: block;';

        this.el.parentNode.appendChild(clone);
        this.height = clone.clientHeight;
        this.el.parentNode.removeChild(clone);

        return this.height;
    };

    slideToggler.prototype.toggle = function(time) {
        var currHeight, disp, el, end, init, ref, repeat, start;

        el = this.el;

        if (!el) {
            return;
        }

        if (!(this.height > 0)) {
            this.height = this.getHeight();
        }

        if (time == null) {
            time = this.height;
        }

        currHeight = el.clientHeight * (getComputedStyle(el).display !== 'none');
        ref = currHeight > this.height / 2 ? [this.height, 0] : [0, this.height];
        start = ref[0];
        end = ref[1];
        disp = end - start;

        this.el.classList[end === 0 ? 'remove' : 'add']('open');
        this.el.style.cssText = "overflow: hidden; display: block; padding-top: 0; padding-bottom: 0";

        init = (new Date).getTime();

        repeat = function() {
            var instance, ref1, repeatLoop, results, step, isCancelAnimation;

            instance = (new Date).getTime() - init;
            step = start + disp * instance / time;

            if (instance <= time) {
                el.style.height = step + 'px';
            } else {
                el.style.cssText = "display: " + (end === 0 ? 'none' : 'block');
            }

            repeatLoop = requestAnimationFrame(repeat);
            ref1 = Math.floor(step);
            isCancelAnimation = indexOf.call((function() {
                results = [];

                for (var i = start; start <= end ? i <= end : i >= end; start <= end ? i++ : i--) {
                    results.push(i);
                }

                return results;
            }).apply(this), ref1);

            if (isCancelAnimation < 0) {
                return cancelAnimationFrame(repeatLoop);
            }
        };

        return repeat();
    };

    return slideToggler;
})();

function toggle(event, data, time) {
    var hide,
        show,
        options = data;

    if (event.target.checked) {
        hide = options.unchecked;
        show = options.checked;
    } else {
        hide = options.checked;
        show = options.unchecked;
    }

    toggler1 = new slideToggler(document.getElementById(hide));
    toggler1.toggle(time);

    toggler2 = new slideToggler(document.getElementById(show));
    toggler2.toggle(time);
}

function isChecked(id, data, toggle) {
    var mockEvent = { target: { checked: true } };
    var startTimeMs = 1;

    if (document.getElementById(id).checked) {
        toggle(mockEvent, data, startTimeMs)
    }
}

function checkChange(id, data) {
    var timeMs = 350;

    document.getElementById(id).addEventListener('change', function(event) {
        toggle(event, data, timeMs);
    });

    isChecked(id, data, toggle);
}

function initMonthlyLimit() {
    var monthlyLimitDefaultValue = document.getElementById('monthlyLimit').value,
        downLimitDefaultValue = document.getElementById('downLimit').value,
        upLimitDefaultValue = document.getElementById('upLimit').value,
        id = 'haveMonthlyLimit',
        data = {'checked': 'monthlyLimitChecked', 'unchecked': 'monthlyLimitUnchecked'},
        timeMs = 350;

        document.getElementById(id).addEventListener('change', function(event) {
            toggle(event, data, timeMs);

            document.getElementById('monthlyLimit').value = monthlyLimitDefaultValue;
            document.getElementById('downLimit').value = downLimitDefaultValue;
            document.getElementById('upLimit').value = upLimitDefaultValue;
        });

        isChecked(id, data, toggle);
}

checkChange('knowSomeone', data = {'checked': 'checkDarknet', 'unchecked': 'noDarknet'});
checkChange('setPassword', data = {'checked': 'givePassword', 'unchecked': ''});
initMonthlyLimit();
