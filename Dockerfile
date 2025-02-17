# Use official Python image
FROM python:3.10

# Set environment variables for Docker
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Copy requirements first to cache dependencies
COPY requirements.txt /app/

# Install dependencies (cache dependencies for faster builds)
RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

# Install WeasyPrint separately (to avoid dependency issues)
RUN pip install weasyprint

# Copy the full project (after installing dependencies)
COPY . /app/

# Collect static files before starting the container
RUN python manage.py collectstatic --noinput

# Ensure Gunicorn is installed
RUN pip install gunicorn

# Expose port
EXPOSE 8000

# Start Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "Ticket_System.wsgi:application"]
