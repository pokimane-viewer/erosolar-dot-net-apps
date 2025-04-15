from flask import Flask, render_template, request, flash, jsonify
import random
import string
import os

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', ''.join(random.choices(string.ascii_letters + string.digits, k=32)))

def full_adder(a, b, cin):
    if not all(bit in (0, 1) for bit in [a, b, cin]):
        raise ValueError("Inputs must be 0 or 1")
    total = a + b + cin
    return total % 2, total // 2

def binary_subtraction(minuend, subtrahend):
    if not isinstance(minuend, int) or not isinstance(subtrahend, int):
        raise TypeError("Minuend and subtrahend must be integers")
    return minuend - subtrahend

def binary_multiplication(multiplicand, multiplier):
    if not isinstance(multiplicand, int) or not isinstance(multiplier, int):
        raise TypeError("Multiplicand and multiplier must be integers")
    if multiplicand < 0 or multiplier < 0:
         raise ValueError("Inputs must be non-negative for this simple simulation")
    return multiplicand * multiplier

def binary_division(dividend, divisor):
    if not isinstance(dividend, int) or not isinstance(divisor, int):
        raise TypeError("Dividend and divisor must be integers")
    if divisor == 0:
        raise ValueError("Division by zero")
    if dividend < 0 or divisor < 0:
         raise ValueError("Inputs must be non-negative for this simple simulation")
    return dividend // divisor, dividend % divisor

def simulate_logic_gate(gate_type, input1, input2=None):
    if not isinstance(input1, int) or input1 not in (0, 1):
         raise ValueError("Input 1 must be 0 or 1")
    if input2 is not None and (not isinstance(input2, int) or input2 not in (0, 1)):
        raise ValueError("Input 2 must be 0 or 1")

    if gate_type == 'NOT':
        if input2 is not None:
            raise ValueError("NOT gate takes only one input")
        return 1 - input1
    elif gate_type == 'AND':
        return input1 & input2
    elif gate_type == 'OR':
        return input1 | input2
    elif gate_type == 'XOR':
        return input1 ^ input2
    elif gate_type == 'NAND':
        return 1 - (input1 & input2)
    elif gate_type == 'NOR':
        return 1 - (input1 | input2)
    elif gate_type == 'XNOR':
        return 1 - (input1 ^ input2)
    else:
        raise ValueError("Unknown gate type")

def simulate_alu_operation(opcode, operand1, operand2):
    if not all(isinstance(op, int) for op in [operand1, operand2]):
        raise ValueError("Operands must be integers")

    if opcode == 'ADD':
        return operand1 + operand2
    elif opcode == 'SUB':
        return operand1 - operand2
    elif opcode == 'AND':
        return operand1 & operand2
    elif opcode == 'OR':
        return operand1 | operand2
    elif opcode == 'XOR':
        return operand1 ^ operand2
    elif opcode == 'SHIFT_LEFT':
        return operand1 << operand2
    elif opcode == 'SHIFT_RIGHT':
        return operand1 >> operand2
    else:
        raise ValueError("Unknown ALU opcode")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/full_adder', methods=['GET', 'POST'])
def full_adder_route():
    result = None
    error = None
    if request.method == 'POST':
        try:
            a = int(request.form.get('a', '0'))
            b = int(request.form.get('b', '0'))
            cin = int(request.form.get('cin', '0'))
            sum_bit, carry_out = full_adder(a, b, cin)
            result = {'sum': sum_bit, 'carry': carry_out}
        except ValueError as e:
            error = str(e)
            flash(error)
        except Exception as e:
            error = "Invalid input format."
            flash(error)
    return render_template('full_adder.html', result=result, error=error)

@app.route('/subtraction', methods=['GET', 'POST'])
def subtraction_route():
    result = None
    error = None
    if request.method == 'POST':
        try:
            minuend_str = request.form.get('minuend', '0')
            subtrahend_str = request.form.get('subtrahend', '0')
            minuend = int(minuend_str, 2)
            subtrahend = int(subtrahend_str, 2)
            difference = binary_subtraction(minuend, subtrahend)
            result = {'difference_decimal': difference, 'difference_binary': bin(difference)}
        except ValueError as e:
            error = str(e)
            flash(error)
        except TypeError as e:
             error = str(e)
             flash(error)
        except Exception as e:
            error = f"Invalid binary input: {e}"
            flash(error)
    return render_template('subtraction.html', result=result, error=error)


@app.route('/multiplication', methods=['GET', 'POST'])
def multiplication_route():
    result = None
    error = None
    if request.method == 'POST':
        try:
            multiplicand_str = request.form.get('multiplicand', '0')
            multiplier_str = request.form.get('multiplier', '0')
            multiplicand = int(multiplicand_str, 2)
            multiplier = int(multiplier_str, 2)
            product = binary_multiplication(multiplicand, multiplier)
            result = {'product': bin(product)[2:]}
        except ValueError as e:
            error = str(e)
            flash(error)
        except TypeError as e:
             error = str(e)
             flash(error)
        except Exception as e:
            error = f"Invalid binary input: {e}"
            flash(error)
    return render_template('multiplication.html', result=result, error=error)

@app.route('/division', methods=['GET', 'POST'])
def division_route():
    result = None
    error = None
    if request.method == 'POST':
        try:
            dividend_str = request.form.get('dividend', '0')
            divisor_str = request.form.get('divisor', '0')
            dividend = int(dividend_str, 2)
            divisor = int(divisor_str, 2)
            quotient, remainder = binary_division(dividend, divisor)
            result = {'quotient': bin(quotient)[2:], 'remainder': bin(remainder)[2:]}
        except ValueError as e:
            error = str(e)
            flash(error)
        except TypeError as e:
             error = str(e)
             flash(error)
        except Exception as e:
            error = f"Invalid binary input: {e}"
            flash(error)
    return render_template('division.html', result=result, error=error)

@app.route('/prototype/logic_gates', methods=['GET', 'POST'])
def prototype_logic_gates():
    result = None
    error = None
    gate_type = request.form.get('gate_type', 'AND')
    input1_val = request.form.get('input1', '0')
    input2_val = request.form.get('input2', '0')

    if request.method == 'POST':
        try:
            input1 = int(input1_val)
            input2 = None
            if gate_type != 'NOT':
                 input2 = int(input2_val)

            output = simulate_logic_gate(gate_type, input1, input2)
            result = {'output': output}
        except ValueError as e:
            error = str(e)
            flash(error)
        except Exception as e:
            error = f"Simulation error: {e}"
            flash(error)

    return render_template('logic_gates.html',
                           result=result,
                           error=error,
                           selected_gate=gate_type,
                           input1=input1_val,
                           input2=input2_val)

@app.route('/hw_sw_codesign/alu_simulator', methods=['GET', 'POST'])
def hw_sw_codesign_alu():
    result = None
    error = None
    opcode = request.form.get('opcode', 'ADD')
    operand1_val = request.form.get('operand1', '0')
    operand2_val = request.form.get('operand2', '0')

    if request.method == 'POST':
        try:
            operand1 = int(operand1_val)
            operand2 = int(operand2_val)
            output = simulate_alu_operation(opcode, operand1, operand2)
            result = {
                'decimal': output,
                'binary': bin(output),
                'hex': hex(output).upper()
            }
        except ValueError as e:
            error = str(e)
            flash(error)
        except Exception as e:
            error = f"ALU simulation error: {e}"
            flash(error)

    return render_template('alu_simulator.html',
                           result=result,
                           error=error,
                           selected_opcode=opcode,
                           operand1=operand1_val,
                           operand2=operand2_val)


@app.route('/formal_verification')
def formal_verification_placeholder():
     flash("Formal Verification requires integration with specialized backend tools.")
     return render_template('placeholder.html', title="Formal Verification / Test Bench Generation")

@app.route('/architecture_explore')
def architecture_explore_placeholder():
     flash("Architecture Exploration requires detailed performance/area/power models.")
     return render_template('placeholder.html', title="Rapid Architecture Exploration")

@app.route('/configure_ip')
def configure_ip_placeholder():
     flash("IP Configuration requires parameter validation and RTL generation capabilities.")
     return render_template('placeholder.html', title="Customer-Facing Configurators")

@app.route('/post_silicon_debug')
def post_silicon_debug_placeholder():
     flash("Post-Silicon Debug/Visualization requires connection to hardware and trace tools.")
     return render_template('placeholder.html', title="Post-Silicon Debug and Visualization")

@app.route('/logic_obfuscation')
def logic_obfuscation_placeholder():
     flash("Logic Obfuscation modeling requires specialized techniques and analysis.")
     return render_template('placeholder.html', title="Logic Obfuscation / Red Teaming")


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')