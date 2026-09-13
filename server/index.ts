import 'dotenv/config'
import { createHash } from 'node:crypto'
import express, { type NextFunction, type Request, type Response } from 'express'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import multer from 'multer'
import { createClient } from '@supabase/supabase-js'
import { db, migrate, seedDatabase } from './db.js'

type Role = 'admin' | 'kasir'
type Payment = 'Tunai' | 'QRIS' | 'Debit / Kredit' | 'E-Wallet'
type AuthUser = { id: number; username: string; displayName: string; role: Role }
type AuthRequest = Request & { user?: AuthUser }
const PORT = Number(process.env.PORT || 3001)
const ORIGIN = process.env.CLIENT_ORIGIN || 'http://localhost:5173'
const API_PUBLIC_ORIGIN = process.env.API_PUBLIC_ORIGIN || `http://localhost:${PORT}`
const JWT_SECRET = process.env.JWT_SECRET
if (!JWT_SECRET || JWT_SECRET.length < 32) throw new Error('JWT_SECRET wajib diisi dengan minimal 32 karakter di .env.')
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (_request, file, callback) => callback(null, file.mimetype.startsWith('image/')),
})
const supabase = process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY
  ? createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY)
  : null
const storageBucket = process.env.SUPABASE_STORAGE_BUCKET || 'product-images'
const MIDTRANS_SERVER_KEY = process.env.MIDTRANS_SERVER_KEY || ''
const MIDTRANS_CLIENT_KEY = process.env.MIDTRANS_CLIENT_KEY || ''
const MIDTRANS_API_URL = process.env.MIDTRANS_IS_PRODUCTION === 'true' ? 'https://app.midtrans.com' : 'https://app.sandbox.midtrans.com'

const app = express()
app.use(cors({ origin: ORIGIN, credentials: true }))
app.use(cookieParser())
app.use(express.json({ limit: '100kb' }))
const ready = migrate().then(seedDatabase)
app.use(async (_request, _response, next) => { try { await ready; next() } catch (error) { next(error) } })

const readCookie = (request: Request, name: string) => request.headers.cookie?.split(';').map(v => v.trim()).find(v => v.startsWith(`${name}=`))?.slice(name.length + 1)
const tokenFor = (user: AuthUser) => jwt.sign(user, JWT_SECRET, { expiresIn: '8h' })
const auth = (request: AuthRequest, response: Response, next: NextFunction) => {
  const token = readCookie(request, 'kk_session')
  if (!token) return response.status(401).json({ error: 'Sesi login diperlukan.' })
  try { request.user = jwt.verify(token, JWT_SECRET) as AuthUser; next() }
  catch { response.status(401).json({ error: 'Sesi telah habis. Silakan login kembali.' }) }
}
const allow = (...roles: Role[]) => (request: AuthRequest, response: Response, next: NextFunction) => roles.includes(request.user!.role) ? next() : response.status(403).json({ error: 'Anda tidak memiliki akses untuk tindakan ini.' })
const fail = (response: Response, status: number, error: string) => response.status(status).json({ error })
const asText = (value: unknown, max = 180) => typeof value === 'string' ? value.trim().slice(0, max) : ''
const asInteger = (value: unknown) => Number.isSafeInteger(Number(value)) ? Number(value) : NaN
const productSelect = `SELECT p.id, p.name, p.sku, c.name AS category, p.price, p.stock, p.image_url AS image FROM products p JOIN categories c ON c.id = p.category_id`
const midtransPaymentMethods: Record<Payment, string[]> = { Tunai: [], QRIS: ['gopay'], 'Debit / Kredit': ['credit_card'], 'E-Wallet': ['gopay', 'shopeepay'] }
async function createSnapTransaction(orderId: string, total: number, items: { id: number; name: string; price: number; quantity: number }[], customerName: string, payment: Payment) {
  if (!MIDTRANS_SERVER_KEY || !MIDTRANS_CLIENT_KEY) throw new Error('Midtrans belum dikonfigurasi. Isi MIDTRANS_SERVER_KEY dan MIDTRANS_CLIENT_KEY di .env.')
  const gatewayResponse = await fetch(`${MIDTRANS_API_URL}/snap/v1/transactions`, {
    method: 'POST',
    headers: { Authorization: `Basic ${Buffer.from(`${MIDTRANS_SERVER_KEY}:`).toString('base64')}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      transaction_details: { order_id: orderId, gross_amount: total },
      item_details: items.map(item => ({ id: String(item.id), price: item.price, quantity: item.quantity, name: item.name.slice(0, 50) })),
      customer_details: { first_name: customerName.slice(0, 50) },
      enabled_payments: midtransPaymentMethods[payment],
    }),
  })
  const payload = await gatewayResponse.json().catch(() => ({})) as { token?: string; redirect_url?: string; error_messages?: string[] }
  if (!gatewayResponse.ok || !payload.token) throw new Error(payload.error_messages?.join(' ') || 'Midtrans gagal membuat transaksi.')
  return payload
}

app.get('/api/health', (_request, response) => response.json({ ok: true }))
app.post('/api/auth/login', async (request, response) => {
  const username = asText(request.body?.username, 60); const password = String(request.body?.password || '')
  if (!username || !password) return fail(response, 400, 'Username dan password wajib diisi.')
  const user = await db.prepare('SELECT id, username, password_hash, display_name, role FROM users WHERE username = ?').get(username) as { id: number; username: string; password_hash: string; display_name: string; role: Role } | undefined
  if (!user || !bcrypt.compareSync(password, user.password_hash)) return fail(response, 401, 'Username atau password salah.')
  const safeUser: AuthUser = { id: user.id, username: user.username, displayName: user.display_name, role: user.role }
  response.cookie('kk_session', tokenFor(safeUser), { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 8 * 60 * 60 * 1000, path: '/' })
  response.json({ user: safeUser })
})
app.post('/api/auth/logout', (_request, response) => { response.clearCookie('kk_session', { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', path: '/' }); response.status(204).end() })
app.get('/api/auth/me', auth, (request: AuthRequest, response) => response.json({ user: request.user }))
app.post('/api/auth/password', auth, async (request: AuthRequest, response) => {
  const currentPassword = String(request.body?.currentPassword || ''), newPassword = String(request.body?.newPassword || '')
  if (newPassword.length < 10) return fail(response, 400, 'Password baru minimal 10 karakter.')
  const row = await db.prepare('SELECT password_hash FROM users WHERE id = ?').get(request.user!.id) as { password_hash: string }
  if (!bcrypt.compareSync(currentPassword, row.password_hash)) return fail(response, 400, 'Password saat ini salah.')
  await db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(bcrypt.hashSync(newPassword, 12), request.user!.id)
  response.status(204).end()
})

app.get('/api/products', auth, async (_request, response) => response.json({ products: await db.prepare(`${productSelect} ORDER BY p.name`).all() }))
app.post('/api/uploads/product-image', auth, allow('admin'), upload.single('image'), async (request, response) => {
  if (!request.file) return fail(response, 400, 'File gambar wajib diisi dan harus berupa gambar.')
  if (!supabase) return fail(response, 500, 'Supabase Storage belum dikonfigurasi.')
  const filePath = `products/${Date.now()}-${Math.random().toString(36).slice(2)}-${request.file.originalname.replace(/[^a-zA-Z0-9._-]/g, '')}`
  const { error } = await supabase.storage.from(storageBucket).upload(filePath, request.file.buffer, { contentType: request.file.mimetype, upsert: false })
  if (error) return fail(response, 502, `Upload gambar gagal: ${error.message}`)
  const { data } = supabase.storage.from(storageBucket).getPublicUrl(filePath)
  response.status(201).json({ image: data.publicUrl })
})
app.post('/api/products', auth, allow('admin'), async (request, response) => {
  const name = asText(request.body?.name), sku = asText(request.body?.sku, 60), category = asText(request.body?.category, 80), price = asInteger(request.body?.price), stock = asInteger(request.body?.stock), image = asText(request.body?.image, 500)
  if (!name || !sku || !category || price < 0 || stock < 0) return fail(response, 400, 'Data produk tidak valid.')
  const categoryRow = await db.prepare('SELECT id FROM categories WHERE name = ?').get(category) as { id: number } | undefined
  if (!categoryRow) return fail(response, 400, 'Kategori tidak ditemukan.')
  try { const result = await db.prepare('INSERT INTO products(name, sku, category_id, price, stock, image_url) VALUES (?, ?, ?, ?, ?, ?) RETURNING id').run(name, sku, categoryRow.id, price, stock, image); response.status(201).json({ product: await db.prepare(`${productSelect} WHERE p.id = ?`).get(result.lastInsertRowid) }) }
  catch { fail(response, 409, 'SKU sudah digunakan.') }
})
app.put('/api/products/:id', auth, allow('admin'), async (request, response) => {
  const id = asInteger(request.params.id), name = asText(request.body?.name), sku = asText(request.body?.sku, 60), category = asText(request.body?.category, 80), price = asInteger(request.body?.price), stock = asInteger(request.body?.stock), image = asText(request.body?.image, 500)
  const categoryRow = await db.prepare('SELECT id FROM categories WHERE name = ?').get(category) as { id: number } | undefined
  if (!Number.isInteger(id) || !name || !sku || !categoryRow || price < 0 || stock < 0) return fail(response, 400, 'Data produk tidak valid.')
  try { const result = await db.prepare("UPDATE products SET name=?, sku=?, category_id=?, price=?, stock=?, image_url=?, updated_at=CURRENT_TIMESTAMP WHERE id=?").run(name, sku, categoryRow.id, price, stock, image, id); if (!result.changes) return fail(response, 404, 'Produk tidak ditemukan.'); response.json({ product: await db.prepare(`${productSelect} WHERE p.id = ?`).get(id) }) }
  catch { fail(response, 409, 'SKU sudah digunakan.') }
})
app.delete('/api/products/:id', auth, allow('admin'), async (request, response) => { const id = asInteger(request.params.id); const result = await db.prepare('DELETE FROM products WHERE id = ?').run(id); result.changes ? response.status(204).end() : fail(response, 404, 'Produk tidak ditemukan.') })
app.get('/api/categories', auth, async (_request, response) => response.json({ categories: await db.prepare('SELECT c.id, c.name, COUNT(p.id) AS productCount FROM categories c LEFT JOIN products p ON p.category_id=c.id GROUP BY c.id ORDER BY c.name').all() }))
app.post('/api/categories', auth, allow('admin'), async (request, response) => { const name = asText(request.body?.name, 80); if (!name) return fail(response, 400, 'Nama kategori wajib diisi.'); try { const result = await db.prepare('INSERT INTO categories(name) VALUES (?) RETURNING id').run(name); response.status(201).json({ category: await db.prepare('SELECT id, name, 0 AS productCount FROM categories WHERE id=?').get(result.lastInsertRowid) }) } catch { fail(response, 409, 'Kategori sudah ada.') } })
app.delete('/api/categories/:id', auth, allow('admin'), async (request, response) => { const id = asInteger(request.params.id); try { const result = await db.prepare('DELETE FROM categories WHERE id=?').run(id); result.changes ? response.status(204).end() : fail(response, 404, 'Kategori tidak ditemukan.') } catch { fail(response, 409, 'Kategori masih digunakan oleh produk.') } })

app.get('/api/settings', auth, async (_request, response) => { const rows = await db.prepare('SELECT key, value FROM settings').all() as { key: string; value: string }[]; const settings = Object.fromEntries(rows.map(row => [row.key, row.key === 'taxRate' ? Number(row.value) : row.value])); response.json({ settings }) })
app.put('/api/settings', auth, allow('admin'), async (request, response) => { const storeName = asText(request.body?.storeName, 120), taxRate = asInteger(request.body?.taxRate); if (!storeName || taxRate < 0 || taxRate > 100) return fail(response, 400, 'Pengaturan tidak valid.'); const set = db.prepare('INSERT INTO settings(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value'); await set.run('storeName', storeName); await set.run('taxRate', String(taxRate)); response.json({ settings: { storeName, taxRate } }) })

app.get('/api/transactions', auth, async (request: AuthRequest, response) => {
  const from = asText(request.query?.from as string, 20), to = asText(request.query?.to as string, 20)
  const dateClause = from && to ? ` AND (t.created_at AT TIME ZONE 'Asia/Jakarta')::date BETWEEN ? AND ?` : from ? ` AND (t.created_at AT TIME ZONE 'Asia/Jakarta')::date >= ?` : to ? ` AND (t.created_at AT TIME ZONE 'Asia/Jakarta')::date <= ?` : ''
  const dateParams: string[] = from && to ? [from, to] : from ? [from] : to ? [to] : []
  const isAdmin = request.user!.role === 'admin'
  const baseQuery = `SELECT t.*, u.display_name AS cashier FROM transactions t JOIN users u ON u.id=t.cashier_id WHERE 1=1`
  const rows = isAdmin
    ? await db.prepare(`${baseQuery}${dateClause} ORDER BY t.created_at DESC`).all(...dateParams)
    : await db.prepare(`${baseQuery} AND t.cashier_id=?${dateClause} ORDER BY t.created_at DESC`).all(request.user!.id, ...dateParams)
  const rowsTyped = rows as { id: number; transaction_number: string; created_at: string; cashier: string; customer_name: string; subtotal: number; discount: number; tax: number; total: number; payment_method: Payment; cash_received: number; change_amount: number; status: string; payment_status: string; gateway_order_id: string | null; cancel_reason: string | null; cancelled_at: string | null }[]
  const items = db.prepare('SELECT product_id AS productId, product_name AS name, product_sku AS sku, unit_price AS price, quantity, line_total AS lineTotal FROM transaction_items WHERE transaction_id=?')
  response.json({ transactions: await Promise.all(rowsTyped.map(async row => ({ id: row.transaction_number, databaseId: row.id, date: row.created_at, cashier: row.cashier, customer: row.customer_name, subtotal: row.subtotal, discount: row.discount, tax: row.tax, total: row.total, payment: row.payment_method, cashReceived: row.cash_received, change: row.change_amount, status: row.status || 'completed', paymentStatus: row.payment_status || 'settlement', gatewayOrderId: row.gateway_order_id, cancelReason: row.cancel_reason || null, cancelledAt: row.cancelled_at || null, items: await items.all(row.id) }))) })
})
app.post('/api/checkout', auth, async (request: AuthRequest, response) => {
  const rawItems = Array.isArray(request.body?.items) ? request.body.items : []
  const discount = asInteger(request.body?.discount || 0)
  const payment = asText(request.body?.payment, 30) as Payment
  const cashReceived = asInteger(request.body?.cashReceived || 0)
  const customerName = asText(request.body?.customerName || 'Pelanggan Umum', 100) || 'Pelanggan Umum'
  if (!rawItems.length || !Number.isInteger(discount) || discount < 0 || !(['Tunai', 'QRIS', 'Debit / Kredit', 'E-Wallet'] as Payment[]).includes(payment)) return fail(response, 400, 'Data checkout tidak valid.')
  try {
    await db.transaction(async () => {
    if (request.user!.role === 'kasir' && !await db.prepare('SELECT id FROM shifts WHERE cashier_id=? AND closed_at IS NULL LIMIT 1').get(request.user!.id)) throw new Error('Buka kasir terlebih dahulu sebelum transaksi.')
    const findProduct = db.prepare('SELECT id, name, sku, price, stock FROM products WHERE id=?')
    let subtotal = 0
    const items: { id: number; name: string; sku: string; price: number; quantity: number }[] = []
    for (const input of rawItems) {
      const id = asInteger(input?.id), quantity = asInteger(input?.quantity)
      if (!Number.isInteger(id) || !Number.isInteger(quantity) || quantity < 1 || quantity > 999) throw new Error('Item checkout tidak valid.')
      const product = await findProduct.get(id) as { id: number; name: string; sku: string; price: number; stock: number } | undefined
      if (!product) throw new Error('Produk tidak ditemukan.')
      if (product.stock < quantity) throw new Error(`Stok ${product.name} tidak mencukupi.`)
      items.push({ ...product, quantity }); subtotal += product.price * quantity
    }
    if (discount > subtotal) throw new Error('Diskon tidak boleh melebihi subtotal.')
    const taxRate = Number(((await db.prepare("SELECT value FROM settings WHERE key='taxRate'").get()) as { value: string }).value)
    const tax = Math.round((subtotal - discount) * taxRate / 100)
    const total = subtotal - discount + tax
    if (payment === 'Tunai' && cashReceived < total) throw new Error('Nominal tunai belum mencukupi.')
    const existing = customerName !== 'Pelanggan Umum' ? await db.prepare('SELECT id FROM customers WHERE name=? ORDER BY id LIMIT 1').get(customerName) as { id: number } | undefined : undefined
    const insertedCustomer = existing ? null : customerName === 'Pelanggan Umum' ? null : await db.prepare('INSERT INTO customers(name) VALUES (?) RETURNING id').run(customerName)
    const customerId = customerName === 'Pelanggan Umum' ? null : existing ? existing.id : Number(insertedCustomer?.lastInsertRowid)
    const orderId = `TRX-${new Date().toISOString().replace(/\D/g, '').slice(0, 14)}-${Math.floor(Math.random() * 900 + 100)}`
    const gateway = payment === 'Tunai' ? null : await createSnapTransaction(orderId, total, items, customerName, payment)
    const status = payment === 'Tunai' ? 'completed' : 'pending'
    const paymentStatus = payment === 'Tunai' ? 'settlement' : 'pending'
    const insertTransaction = await db.prepare('INSERT INTO transactions(transaction_number,cashier_id,customer_id,customer_name,subtotal,discount,tax,total,payment_method,cash_received,change_amount,status,payment_status,gateway_order_id,gateway_token,gateway_payload) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING id').run(orderId, request.user!.id, customerId, customerName, subtotal, discount, tax, total, payment, payment === 'Tunai' ? cashReceived : 0, payment === 'Tunai' ? cashReceived - total : 0, status, paymentStatus, gateway?.token ? orderId : null, gateway?.token || null, gateway ? JSON.stringify(gateway) : null)
    const transactionId = Number(insertTransaction.lastInsertRowid)
    const insertItem = db.prepare('INSERT INTO transaction_items(transaction_id,product_id,product_name,product_sku,unit_price,quantity,line_total) VALUES (?,?,?,?,?,?,?)')
    const decrease = db.prepare('UPDATE products SET stock=stock-?, updated_at=CURRENT_TIMESTAMP WHERE id=? AND stock>=?')
    for (const item of items) { await insertItem.run(transactionId, item.id, item.name, item.sku, item.price, item.quantity, item.price * item.quantity); if (!(await decrease.run(item.quantity, item.id, item.quantity)).changes) throw new Error(`Stok ${item.name} berubah. Coba lagi.`) }
    if (payment === 'Tunai' && customerId) await db.prepare('UPDATE customers SET visits=visits+1, total_spend=total_spend+? WHERE id=?').run(total, customerId)
    response.status(201).json({ transaction: { id: orderId, databaseId: transactionId, date: new Date().toISOString(), cashier: request.user!.displayName, customer: customerName, items: items.map(item => ({ id: item.id, name: item.name, sku: item.sku, price: item.price, quantity: item.quantity, lineTotal: item.price * item.quantity })), subtotal, discount, tax, total, payment, cashReceived: payment === 'Tunai' ? cashReceived : 0, change: payment === 'Tunai' ? cashReceived - total : 0, status, paymentStatus, snapToken: gateway?.token || null, clientKey: gateway ? MIDTRANS_CLIENT_KEY : null } })
    })
  } catch (error) { fail(response, 400, error instanceof Error ? error.message : 'Checkout gagal.') }
})
app.post('/api/payments/midtrans/notification', async (request, response) => {
  const orderId = asText(request.body?.order_id, 80), statusCode = asText(request.body?.status_code, 10), grossAmount = asText(request.body?.gross_amount, 30), signature = asText(request.body?.signature_key, 160)
  const expectedSignature = createHash('sha512').update(`${orderId}${statusCode}${grossAmount}${MIDTRANS_SERVER_KEY}`).digest('hex')
  if (!MIDTRANS_SERVER_KEY || !signature || signature !== expectedSignature) return fail(response, 401, 'Signature webhook tidak valid.')
  const transaction = await db.prepare('SELECT id, customer_id, total, status FROM transactions WHERE gateway_order_id=?').get(orderId) as { id: number; customer_id: number | null; total: number; status: string } | undefined
  if (!transaction) return fail(response, 404, 'Transaksi gateway tidak ditemukan.')
  if (transaction.status === 'completed' || transaction.status === 'cancelled') return response.json({ ok: true })
  const transactionStatus = request.body?.transaction_status as string
  const settled = transactionStatus === 'settlement' || transactionStatus === 'capture'
  const rejected = ['deny', 'cancel', 'expire', 'failure'].includes(transactionStatus)
  if (settled) {
    await db.prepare("UPDATE transactions SET status='completed', payment_status=?, gateway_payload=? WHERE id=?").run(transactionStatus, JSON.stringify(request.body), transaction.id)
    if (transaction.customer_id) await db.prepare('UPDATE customers SET visits=visits+1, total_spend=total_spend+? WHERE id=?').run(transaction.total, transaction.customer_id)
  } else if (rejected) {
      await db.transaction(async () => {
        const items = await db.prepare('SELECT product_id, quantity FROM transaction_items WHERE transaction_id=? AND product_id IS NOT NULL').all(transaction.id) as { product_id: number; quantity: number }[]
        for (const item of items) await db.prepare('UPDATE products SET stock=stock+?, updated_at=CURRENT_TIMESTAMP WHERE id=?').run(item.quantity, item.product_id)
        await db.prepare("UPDATE transactions SET status='cancelled', payment_status=?, cancel_reason=?, cancelled_at=CURRENT_TIMESTAMP, gateway_payload=? WHERE id=?").run(transactionStatus, `Midtrans: ${transactionStatus}`, JSON.stringify(request.body), transaction.id)
      })
  } else {
    await db.prepare('UPDATE transactions SET payment_status=?, gateway_payload=? WHERE id=?').run(transactionStatus || 'pending', JSON.stringify(request.body), transaction.id)
  }
  response.json({ ok: true })
})
app.get('/api/transactions/:id/payment', auth, async (request: AuthRequest, response) => {
  const id = asInteger(request.params.id)
  const transaction = await db.prepare('SELECT t.id, t.status, t.payment_status AS paymentStatus, t.cancel_reason AS cancelReason, t.cashier_id AS cashierId FROM transactions t WHERE t.id=?').get(id) as { id: number; status: string; paymentStatus: string; cancelReason: string | null; cashierId: number } | undefined
  if (!transaction || (request.user!.role !== 'admin' && transaction.cashierId !== request.user!.id)) return fail(response, 404, 'Transaksi tidak ditemukan.')
  response.json({ payment: { status: transaction.status, paymentStatus: transaction.paymentStatus, cancelReason: transaction.cancelReason } })
})
app.get('/api/customers', auth, allow('admin'), async (_request, response) => response.json({ customers: await db.prepare('SELECT id, name, phone, visits, total_spend AS spend FROM customers ORDER BY total_spend DESC, name').all() }))
app.post('/api/customers', auth, allow('admin'), async (request, response) => { const name = asText(request.body?.name, 100), phone = asText(request.body?.phone, 30); if (!name) return fail(response, 400, 'Nama pelanggan wajib diisi.'); const result = await db.prepare('INSERT INTO customers(name,phone) VALUES (?,?) RETURNING id').run(name, phone); response.status(201).json({ customer: await db.prepare('SELECT id,name,phone,visits,total_spend AS spend FROM customers WHERE id=?').get(result.lastInsertRowid) }) })
app.get('/api/dashboard', auth, async (request: AuthRequest, response) => { const scope = request.user!.role === 'admin' ? ['', []] : [' AND cashier_id=?', [request.user!.id]] as [string, number[]]; const today = await db.prepare(`SELECT COUNT(*) AS transactions, COALESCE(SUM(total),0) AS sales FROM transactions WHERE (created_at AT TIME ZONE 'Asia/Jakarta')::date=(CURRENT_TIMESTAMP AT TIME ZONE 'Asia/Jakarta')::date${scope[0]}`).get(...scope[1]) as { transactions: number; sales: number }; const stock = (await db.prepare('SELECT COALESCE(SUM(stock),0) AS stock FROM products').get() as { stock: number }).stock; const customers = (await db.prepare('SELECT COUNT(*) AS count FROM customers').get() as { count: number }).count; response.json({ dashboard: { ...today, stock, customers } }) })
app.get('/api/reports', auth, allow('admin'), async (request, response) => {
  const from = asText(request.query?.from as string, 20), to = asText(request.query?.to as string, 20)
  const dateClause = from && to ? ` AND (created_at AT TIME ZONE 'Asia/Jakarta')::date BETWEEN ? AND ?` : from ? ` AND (created_at AT TIME ZONE 'Asia/Jakarta')::date >= ?` : to ? ` AND (created_at AT TIME ZONE 'Asia/Jakarta')::date <= ?` : ''
  const dateParams: string[] = from && to ? [from, to] : from ? [from] : to ? [to] : []
  const cashierId = asInteger(request.query?.cashierId as string)
  const filters = ['status=\'completed\'']; const params: (string | number)[] = []
  if (from) { filters.push("(created_at AT TIME ZONE 'Asia/Jakarta')::date >= ?"); params.push(from) }
  if (to) { filters.push("(created_at AT TIME ZONE 'Asia/Jakarta')::date <= ?"); params.push(to) }
  if (Number.isInteger(cashierId)) { filters.push('cashier_id=?'); params.push(cashierId) }
  const where = ` WHERE ${filters.join(' AND ')}`
  const totals = await db.prepare(`SELECT COUNT(*) AS transactions, COALESCE(SUM(total),0) AS revenue, COALESCE(SUM(subtotal),0) AS gross FROM transactions${where}`).get(...params)
  const transactionFilters = filters.map(filter => filter.replace(/created_at/g, 't.created_at').replace(/status/g, 't.status').replace(/cashier_id/g, 't.cashier_id'))
  const topProducts = await db.prepare(`SELECT ti.product_name AS name, SUM(ti.quantity) AS quantity FROM transaction_items ti JOIN transactions t ON t.id=ti.transaction_id WHERE ${transactionFilters.join(' AND ')} GROUP BY ti.product_name ORDER BY quantity DESC LIMIT 10`).all(...params)
  const trend = await db.prepare(`SELECT (created_at AT TIME ZONE 'Asia/Jakarta')::date AS date, COUNT(*) AS transactions, COALESCE(SUM(total),0) AS revenue FROM transactions${where} GROUP BY (created_at AT TIME ZONE 'Asia/Jakarta')::date ORDER BY (created_at AT TIME ZONE 'Asia/Jakarta')::date`).all(...params)
  const cashiers = await db.prepare("SELECT id, display_name AS name FROM users WHERE role='kasir' ORDER BY display_name").all()
  const lowStock = await db.prepare(`${productSelect} WHERE p.stock<10 ORDER BY p.stock ASC`).all()
  response.json({ report: { totals, topProducts, trend, cashiers, selectedCashierId: Number.isInteger(cashierId) ? cashierId : null, from: from || null, to: to || null, lowStock } })
})

// Cancellation — Fitur 1
app.post('/api/transactions/:id/cancel', auth, async (request: AuthRequest, response) => {
  const id = asInteger(request.params.id)
  const reason = asText(request.body?.reason, 500)
  if (!Number.isInteger(id) || !reason) return fail(response, 400, 'ID transaksi dan alasan pembatalan wajib diisi.')
  const trx = await db.prepare('SELECT id, cashier_id, status, created_at FROM transactions WHERE id=?').get(id) as { id: number; cashier_id: number; status: string; created_at: string } | undefined
  if (!trx) return fail(response, 404, 'Transaksi tidak ditemukan.')
  if (trx.status === 'cancelled') return fail(response, 409, 'Transaksi sudah dibatalkan.')
  const isAdmin = request.user!.role === 'admin'
  const isOwner = trx.cashier_id === request.user!.id
  const isToday = new Date(trx.created_at).toDateString() === new Date().toDateString()
  if (!isAdmin && (!isOwner || !isToday)) return fail(response, 403, 'Kasir hanya bisa membatalkan transaksi miliknya hari ini.')
  try {
    await db.transaction(async () => {
      const items = await db.prepare('SELECT product_id, quantity FROM transaction_items WHERE transaction_id=? AND product_id IS NOT NULL').all(id) as { product_id: number; quantity: number }[]
      for (const item of items) await db.prepare('UPDATE products SET stock=stock+?, updated_at=CURRENT_TIMESTAMP WHERE id=?').run(item.quantity, item.product_id)
      await db.prepare("UPDATE transactions SET status='cancelled', cancel_reason=?, cancelled_at=CURRENT_TIMESTAMP, cancelled_by=? WHERE id=?").run(reason, request.user!.id, id)
    })
    response.status(204).end()
  } catch { fail(response, 500, 'Pembatalan gagal.') }
})

// Shift Management — Fitur 2
app.get('/api/shifts/active', auth, async (request: AuthRequest, response) => {
  const shift = await db.prepare('SELECT id, cashier_id, opened_at, opening_cash FROM shifts WHERE cashier_id=? AND closed_at IS NULL ORDER BY opened_at DESC LIMIT 1').get(request.user!.id) as { id: number; cashier_id: number; opened_at: string; opening_cash: number } | undefined
  response.json({ shift: shift ? { id: shift.id, openedAt: shift.opened_at, openingCash: shift.opening_cash } : null })
})
app.post('/api/shifts/open', auth, async (request: AuthRequest, response) => {
  const existing = await db.prepare('SELECT id FROM shifts WHERE cashier_id=? AND closed_at IS NULL').get(request.user!.id)
  if (existing) return fail(response, 409, 'Anda masih memiliki shift aktif. Tutup shift terlebih dahulu.')
  const openingCash = asInteger(request.body?.openingCash ?? 0)
  if (openingCash < 0) return fail(response, 400, 'Kas awal tidak boleh negatif.')
  const result = await db.prepare('INSERT INTO shifts(cashier_id, opening_cash) VALUES (?, ?) RETURNING id').run(request.user!.id, openingCash)
  const shift = await db.prepare('SELECT id, cashier_id, opened_at, opening_cash FROM shifts WHERE id=?').get(result.lastInsertRowid) as { id: number; cashier_id: number; opened_at: string; opening_cash: number }
  response.status(201).json({ shift: { id: shift.id, openedAt: shift.opened_at, openingCash: shift.opening_cash } })
})
app.post('/api/shifts/close', auth, async (request: AuthRequest, response) => {
  const shift = await db.prepare('SELECT id, opened_at, opening_cash FROM shifts WHERE cashier_id=? AND closed_at IS NULL ORDER BY opened_at DESC LIMIT 1').get(request.user!.id) as { id: number; opened_at: string; opening_cash: number } | undefined
  if (!shift) return fail(response, 404, 'Tidak ada shift aktif yang ditemukan.')
  const closingCash = asInteger(request.body?.closingCash ?? 0)
  const notes = asText(request.body?.notes, 500)
  if (closingCash < 0) return fail(response, 400, 'Kas fisik tidak boleh negatif.')
  const { total: shiftRevenue } = await db.prepare("SELECT COALESCE(SUM(total),0) AS total FROM transactions WHERE cashier_id=? AND status='completed' AND payment_method='Tunai' AND created_at >= ?").get(request.user!.id, shift.opened_at) as { total: number }
  const expectedCash = shift.opening_cash + shiftRevenue
  await db.prepare('UPDATE shifts SET closed_at=CURRENT_TIMESTAMP, closing_cash=?, expected_cash=?, notes=? WHERE id=?').run(closingCash, expectedCash, notes, shift.id)
  response.json({ summary: { openingCash: shift.opening_cash, shiftRevenue, expectedCash, closingCash, difference: closingCash - expectedCash } })
})
app.use((error: unknown, _request: Request, response: Response, _next: NextFunction) => { console.error(error); response.status(500).json({ error: 'Terjadi kesalahan server.' }) })
export { app, ready }

if (!process.env.VERCEL) ready.then(() => app.listen(PORT, () => console.log(`KasirKita API berjalan di http://localhost:${PORT}`)))
