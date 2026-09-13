FROM shmatdmi/codesentry-sast:941acb5

COPY dist /app/dist
COPY public /app/public

ENV NODE_ENV=production \
    HOSTNAME=0.0.0.0 \
    PORT=3000

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/').then((response) => { if (!response.ok) process.exit(1); }).catch(() => process.exit(1));"