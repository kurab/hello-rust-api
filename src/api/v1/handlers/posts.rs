/*
 * Responsibility
 * - /posts 系 CRUD handler
 * - Path の :path_id は公開 ID → extractor で復号化して内部 ID に変換して受け取る
 * - 認可が必要ならここで AuthContext を参照して service/repo に渡す
 */
