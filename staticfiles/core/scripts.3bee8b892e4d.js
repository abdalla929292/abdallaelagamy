document.addEventListener('DOMContentLoaded', function() {
    // Drag-and-drop functionality for tickets
    var el = document.getElementById('ticket-list');
    if (el) {
        new Sortable(el, {
            animation: 150,
            onEnd: function(evt) {
                var order = [];
                $('#ticket-list li').each(function(index, element) {
                    order.push($(element).data('id'));
                });
                $.ajax({
                    url: '/tickets/order/',
                    method: 'POST',
                    data: {
                        order: order,
                        csrfmiddlewaretoken: $('[name=csrfmiddlewaretoken]').val()
                    },
                    success: function(response) {
                        console.log('Order updated:', response);
                    },
                    error: function(xhr, status, error) {
                        console.error('Error updating order:', error);
                    }
                });
            }
        });
    }

    // AJAX form submission
    $('form').on('submit', function(event) {
        event.preventDefault();
        var form = $(this);
        $.ajax({
            url: form.attr('action'),
            method: form.attr('method'),
            data: new FormData(this),
            contentType: false,
            processData: false,
            success: function(response) {
                console.log('Form submitted successfully:', response);
                if (response.redirect_url) {
                    window.location.href = response.redirect_url;
                } else {
                    location.reload();
                }
            },
            error: function(xhr, status, error) {
                console.error('Error submitting form:', error);
            }
        });
    });

    // Inline editing
    $('.editable').on('click', function() {
        var $el = $(this);
        var $input = $('<input>', {
            type: 'text',
            value: $el.text(),
            blur: function() {
                var $this = $(this);
                $.ajax({
                    url: $el.data('url'),
                    method: 'POST',
                    data: {
                        value: $this.val(),
                        csrfmiddlewaretoken: $('[name=csrfmiddlewaretoken]').val()
                    },
                    success: function(response) {
                        $el.text($this.val());
                        $this.remove();
                    },
                    error: function(xhr, status, error) {
                        console.error('Error updating value:', error);
                    }
                });
            },
            keyup: function(e) {
                if (e.which === 13) $input.blur();
            }
        }).appendTo($el.empty()).focus();
    });

    // Handle apply by yourself checkbox
    const applyForCheckbox = document.getElementById('apply_for_checkbox');
    const appliedForRow = document.getElementById('applied-for-row');
    if (applyForCheckbox && appliedForRow) {
        applyForCheckbox.addEventListener('change', function() {
            if (applyForCheckbox.checked) {
                document.getElementById('id_applied_for').disabled = true;
                appliedForRow.style.display = 'none';
            } else {
                document.getElementById('id_applied_for').disabled = false;
                appliedForRow.style.display = 'table-row';
            }
        });
        if (applyForCheckbox.checked) {
            appliedForRow.style.display = 'none';
        }
    }

    // Handle department and request type changes
    const departmentField = document.getElementById('id_department');
    const requestTypeField = document.getElementById('id_request_type');
    const subRequestTypeField = document.getElementById('id_sub_request_type');
    const positionField = document.getElementById('id_position');
    const subPositionField = document.getElementById('id_sub_position');

    if (departmentField) {
        departmentField.addEventListener('change', function() {
            const departmentId = this.value;
            fetch(`/request_types/${departmentId}/`)
                .then(response => response.json())
                .then(data => {
                    requestTypeField.innerHTML = '<option value="">Select Request Type</option>';
                    data.forEach(request => {
                        const option = document.createElement('option');
                        option.value = request.id;
                        option.textContent = request.name;
                        requestTypeField.appendChild(option);
                    });
                });
        });
    }

    if (requestTypeField) {
        requestTypeField.addEventListener('change', function() {
            const requestTypeId = this.value;
            fetch(`/sub_request_types/${requestTypeId}/`)
                .then(response => response.json())
                .then(data => {
                    subRequestTypeField.innerHTML = '<option value="">Select Sub Request Type</option>';
                    data.forEach(subRequest => {
                        const option = document.createElement('option');
                        option.value = subRequest.id;
                        option.textContent = subRequest.name;
                        subRequestTypeField.appendChild(option);
                    });
                });
        });
    }

    if (positionField) {
        positionField.addEventListener('change', function() {
            const positionId = this.value;
            fetch(`/sub_positions/${positionId}/`)
                .then(response => response.json())
                .then(data => {
                    subPositionField.innerHTML = '<option value="">Select Sub Position</option>';
                    data.forEach(subPosition => {
                        const option = document.createElement('option');
                        option.value = subPosition.id;
                        option.textContent = subPosition.name;
                        subPositionField.appendChild(option);
                    });
                });
        });
    }

    // Dynamic calculations for financial warehouse
    function updateFinancialWarehouseCalculations() {
        const quantity = parseFloat(document.getElementById('id_quantity').value) || 0;
        const price = parseFloat(document.getElementById('id_price').value) || 0;
        const vatPercentage = parseFloat(document.getElementById('id_vat_percentage').value) || 0;

        const netPrice = quantity * price;
        const totalVat = netPrice * (vatPercentage / 100);
        const totalPrice = netPrice + totalVat;

        document.getElementById('id_net_price').value = netPrice.toFixed(2);
        document.getElementById('id_total_vat').value = totalVat.toFixed(2);
        document.getElementById('id_total_price').value = totalPrice.toFixed(2);
    }

    const financialWarehouseFields = ['id_quantity', 'id_price', 'id_vat_percentage'];
    financialWarehouseFields.forEach(fieldId => {
        const field = document.getElementById(fieldId);
        if (field) {
            field.addEventListener('input', updateFinancialWarehouseCalculations);
        }
    });

    // Dynamic calculations for HR warehouse
    function updateHRWarehouseDates() {
        const lastCheckupDate = new Date(document.getElementById('id_last_checkup_date').value);
        const durationOfCheckup = parseInt(document.getElementById('id_duration_of_checkup').value) || 0;
        const endCheckupDate = new Date(lastCheckupDate);
        endCheckupDate.setDate(endCheckupDate.getDate() + durationOfCheckup);
        document.getElementById('id_end_checkup_date').value = endCheckupDate.toISOString().split('T')[0];

        const licenseLastCheckup = new Date(document.getElementById('id_license_last_checkup').value);
        const durationOfLicense = parseInt(document.getElementById('id_duration_of_license').value) || 0;
        const endLicenseDate = new Date(licenseLastCheckup);
        endLicenseDate.setDate(endLicenseDate.getDate() + durationOfLicense);
        document.getElementById('id_end_license_date').value = endLicenseDate.toISOString().split('T')[0];

        const insuranceDateRenew = new Date(document.getElementById('id_insurance_date_renew').value);
        const durationOfInsurance = parseInt(document.getElementById('id_duration_of_insurance').value) || 0;
        const endInsuranceDate = new Date(insuranceDateRenew);
        endInsuranceDate.setDate(endInsuranceDate.getDate() + durationOfInsurance);
        document.getElementById('id_end_insurance_date').value = endInsuranceDate.toISOString().split('T')[0];
    }

    const hrWarehouseFields = [
        'id_last_checkup_date', 'id_duration_of_checkup',
        'id_license_last_checkup', 'id_duration_of_license',
        'id_insurance_date_renew', 'id_duration_of_insurance'
    ];
    hrWarehouseFields.forEach(fieldId => {
        const field = document.getElementById(fieldId);
        if (field) {
            field.addEventListener('input', updateHRWarehouseDates);
        }
    });

    // Handle import and export buttons
    document.getElementById('import-button').addEventListener('click', function() {
        document.getElementById('import-file-input').click();
    });

    document.getElementById('import-file-input').addEventListener('change', function() {
        document.getElementById('import-form').submit();
    });

    document.getElementById('export-button').addEventListener('click', function() {
        window.location.href = '/export/';
    });

    // Signature pad initialization
    var canvas = document.querySelector("canvas");
    var signaturePad = new SignaturePad(canvas);

    document.getElementById('clear-signature').addEventListener('click', function() {
        signaturePad.clear();
    });

    document.getElementById('save-signature').addEventListener('click', function() {
        if (signaturePad.isEmpty()) {
            alert("Please provide a signature first.");
        } else {
            var dataUrl = signaturePad.toDataURL();
            document.getElementById('signature-input').value = dataUrl;
            document.getElementById('signature-form').submit();
        }
    });

    // Fetch notifications
    function fetchNotifications() {
        $.ajax({
            url: '/notifications/',
            method: 'GET',
            success: function(data) {
                const notifications = data.notifications;
                const notificationBadge = document.querySelector('.notification-badge');
                const notificationDropdown = document.querySelector('.notification-dropdown-menu');

                if (notifications.length > 0) {
                    notificationBadge.textContent = notifications.length;
                    notificationBadge.style.display = 'flex';
                    document.querySelector('.notification-icon').src = '{% static "images/file-VauDuqjEVHLBPhToj2GH1QeS.png" %}';

                    notificationDropdown.innerHTML = '';
                    notifications.forEach(notification => {
                        const notificationItem = document.createElement('a');
                        notificationItem.classList.add('dropdown-item');
                        notificationItem.href = notification.url;
                        notificationItem.textContent = notification.message;
                        notificationDropdown.appendChild(notificationItem);
                    });
                } else {
                    notificationBadge.style.display = 'none';
                    document.querySelector('.notification-icon').src = '{% static "images/file-xfbuT2xkztL7QQQpNTe7QQw9.png" %}';
                    notificationDropdown.innerHTML = '<a class="dropdown-item" href="#">No notifications</a>';
                }
            },
            error: function(xhr, status, error) {
                console.error('Error fetching notifications:', error);
            }
        });
    }

    // Toggle notification dropdown on button click
    document.querySelector('.notification-btn').addEventListener('click', function() {
        const notificationDropdown = document.querySelector('.notification-dropdown-menu');
        notificationDropdown.classList.toggle('show');

        if (notificationDropdown.classList.contains('show')) {
            document.querySelector('.notification-icon').src = '{% static "images/file-xfbuT2xkztL7QQQpNTe7QQw9.png" %}';
            const notificationBadge = document.querySelector('.notification-badge');
            notificationBadge.style.display = 'none';
            notificationBadge.textContent = '0';
        }
    });

    // Fetch notifications initially
    fetchNotifications();

    // Periodically fetch notifications
    setInterval(fetchNotifications, 30000); // Fetch notifications every 30 seconds
});

$(document).ready(function() {
    $('.navbar-toggler').click(function() {
        $('nav ul').toggleClass('show');
    });
});

function printTable(tableId) {
    var divToPrint = document.getElementById(tableId);
    var newWin = window.open("");
    newWin.document.write('<html><head><title>Print Table</title>');
    newWin.document.write('<link rel="stylesheet" type="text/css" href="' + static_url('core/styles.css') + '">');
    newWin.document.write('</head><body>');
    newWin.document.write(divToPrint.outerHTML);
    newWin.document.write('</body></html>');
    newWin.print();
    newWin.close();
}


document.addEventListener("DOMContentLoaded", function() {
    function calculateEndDate(startDateId, durationId, endDateId) {
        let startDateElem = document.getElementById(startDateId);
        let durationElem = document.getElementById(durationId);
        let endDateElem = document.getElementById(endDateId);

        if (!startDateElem || !durationElem || !endDateElem) return; // Ensure elements exist

        let startDate = startDateElem.value;
        let duration = durationElem.value ? parseInt(durationElem.value, 10) : 0;

        if (startDate && duration > 0) {
            let startDateObj = new Date(startDate);
            startDateObj.setMonth(startDateObj.getMonth() + duration); // Add months

            let formattedDate = startDateObj.toISOString().split("T")[0]; // Convert to YYYY-MM-DD
            endDateElem.value = formattedDate; // Auto-fill
        }
    }

    function setupAutoUpdate(startField, durationField, endField) {
        let startElem = document.getElementById(startField);
        let durationElem = document.getElementById(durationField);

        if (startElem && durationElem) {
            startElem.addEventListener("change", function() {
                calculateEndDate(startField, durationField, endField);
            });
            durationElem.addEventListener("input", function() {
                calculateEndDate(startField, durationField, endField);
            });
        }
    }

    // 🔄 Setup Listeners for Auto-Update
    setupAutoUpdate("id_last_checkup_date", "id_duration_of_checkup", "id_end_checkup_date");
    setupAutoUpdate("id_license_last_checkup", "id_duration_of_license", "id_end_license_date");
    setupAutoUpdate("id_insurance_date_renew", "id_duration_of_insurance", "id_end_insurance_date");
});
